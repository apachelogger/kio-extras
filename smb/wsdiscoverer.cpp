/*
    Copyright 2019 Harald Sitter <sitter@kde.org

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 3 of
    the License or any later version accepted by the membership of
    KDE e.V. (or its successor approved by the membership of KDE
    e.V.), which shall act as a proxy defined in Section 14 of
    version 3 of the license.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "wsdiscoverer.h"

#include <QDebug>
#include <QSharedPointer>
#include <WSDiscoveryClient>
#include <WSDiscoveryProbeJob>
#include <WSDiscoveryTargetService>
#include <QJsonArray>
#include <QJsonDocument>

#include <QUuid>
#include <KDSoapClient/KDSoapMessage>
#include <KDSoapClient/KDSoapMessageAddressingProperties>
#include <KDSoapClient/KDSoapClientInterface>
#include <KDSoapClient/KDSoapNamespaceManager>
#include <QHostInfo>
#include <QtConcurrent>
#include <QFutureWatcher>


// Publication service data resolver!
// Specifically we'll ask the endpoint for PBSData via ws-transfer/Get.
// The implementation is the bare minimum for our purposes!
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pbsd
class PBSDResolver
{
public:
    /**
     * @param endpointUrl valid xaddr as advertised over ws-discovery (http://$ip/$referenceUuid)
     * @param destination endpoint reference urn as sent over ws-discovery ($referenceUuid)
     */
    PBSDResolver(const QUrl &endpointUrl, const QString &destination)
        : m_endpointUrl(endpointUrl)
        , m_destination(destination)
    {
    }

    WSDiscovery *run()
    {
        // NB: when windows talks to windows they use lms:LargeMetadataSupport we probably don't
        // need this for the data we want, so it's left out. The actual messagse a windows
        // machine creates would be using "http://schemas.microsoft.com/windows/lms/2007/08"
        // as messageNamespace and set an additional header <LargeMetadataSupport/> on the message.
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dpwssn/f700463d-cbbf-4545-ab47-b9a6fbf1ac7b

        qDebug() << m_endpointUrl.toString();
        KDSoapClientInterface client(m_endpointUrl.toString(), QStringLiteral("http://schemas.xmlsoap.org/ws/2004/09/transfer"));
        client.setSoapVersion(KDSoapClientInterface::SoapVersion::SOAP1_2);
        client.setTimeout(8000);

        KDSoapMessage message;
        KDSoapMessageAddressingProperties addressing;
        addressing.setAddressingNamespace(KDSoapMessageAddressingProperties::Addressing200408);
        addressing.setAction(QStringLiteral("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"));
        addressing.setMessageID(QStringLiteral("urn:uuid:") + QUuid::createUuid().toString(QUuid::WithoutBraces));
        addressing.setDestination(m_destination);
        addressing.setReplyEndpointAddress(KDSoapMessageAddressingProperties::predefinedAddressToString(
                                               KDSoapMessageAddressingProperties::Anonymous,
                                               KDSoapMessageAddressingProperties::Addressing200408));
        addressing.setSourceEndpointAddress(QStringLiteral("urn:uuid:") + QUuid::createUuid().toString(QUuid::WithoutBraces));
        message.setMessageAddressingProperties(addressing);

        KDSoapMessage response = client.call(QString(), message);
        if (response.isFault()) {
            qDebug() << response.arguments();
            qWarning() << response.faultAsString();
            // No return! We'd disqualify systems that do not implement pbsd.
        }

        // The response xml would be nesting Metdata<MetadataSection<Relationship<Host<Computer
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pbsd/ec0810ba-2427-46f5-8d47-cc94919ee4c1
        // The value therein is $netbiosname/Domain:$domain or $netbiosname\Workgroup:$workgroup or $netbiosname\NotJoined
        // For simplicity's sake we'll manually pop the value (or empty) out, if we get a name it's grand
        // otherwise we'll attempt reverse resolution from the IP (which ideally would yield results
        // over systemd-resolved's llmnr).

        QString computer;
        for (auto section : response.childValues()) {
            computer = section
                    .childValues().child("Relationship")
                    .childValues().child("Host")
                    .childValues().child("Computer").value().toString();
            if (!computer.isEmpty()) { break; }
        }

        if (computer.isEmpty()) {
            // Chances are if we get here the remote doesn't implement PBSD.
            // This is a bit of a problem in so far as we do not know if the
            // remote actually supports SMB. As far as I can tell

            // try to resolver via QHostInfo (which ideally does a LMNR lookup via libc/systemd)
            qDebug() << "host:" << computer;
            auto hostInfo = QHostInfo::fromName(m_endpointUrl.host());
            if (hostInfo.error() == QHostInfo::NoError) {
                qDebug() << "resolved hostName to " << hostInfo.hostName();
                computer = hostInfo.hostName();
            } else {
                qDebug() << "failed to resolve";
            }
        }

        return new WSDiscovery(computer, m_endpointUrl.host());
    }

private:
    const QUrl m_endpointUrl;
    const QString m_destination;
};

WSDiscoverer::WSDiscoverer()
    : m_client(new WSDiscoveryClient(this))
    , m_probeJob(new WSDiscoveryProbeJob(m_client))

{
    connect(m_probeJob, &WSDiscoveryProbeJob::matchReceived, this, &WSDiscoverer::matchReceived);
    // We only want devices. This will be further
    KDQName type("wsdp:Device");
    type.setNameSpace("http://schemas.xmlsoap.org/ws/2006/02/devprof");
    m_probeJob->addType(type);

    // We technically would probably also want to filter pub:Computer.
    // But! I am not sure if e.g. a NAS would publish itself as computer.
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pbsd

    // If we haven't had a probematch in some seconds there's likely no more replies
    // coming and all hosts are known. Naturally resolvers may still be running and
    // get blocked on during stop(). Resolvers themselves have a timeout via
    // kdsoap.
    // NB: only started after first match! If we have no matches the slave will
    // stop us eventually anyway.
    m_probeMatchTimer.setInterval(2000);
    m_probeMatchTimer.setSingleShot(true);
    connect(&m_probeMatchTimer, &QTimer::timeout, this, &WSDiscoverer::finished);
}

void WSDiscoverer::start()
{
    m_client->start();
    m_probeJob->start();
}

void WSDiscoverer::stop()
{
    qDebug() << Q_FUNC_INFO;
    m_probeJob->stop();
    m_probeMatchTimer.stop();
    // Wait for all futures to finish. We do set a suitable timeout in the resolver so
    // this doesn't take forever.
    for (auto future : m_futures) {
        future.waitForFinished();
    }
}

bool WSDiscoverer::isFinished()
{
    return m_startedTimer && !m_probeMatchTimer.isActive();
}

void WSDiscoverer::matchReceived(const QSharedPointer<WSDiscoveryTargetService> &matchedService)
{
    // (re)start match timer to finish-early if at all possible.
    m_probeMatchTimer.start();
    m_startedTimer = true;

    if (m_seenEndpoints.contains(matchedService->endpointReference())) {
        return;
    }
    m_seenEndpoints << matchedService->endpointReference();

    QUrl addr;
    for(auto xAddr : matchedService->xAddrList()) {
        qDebug() << "  XAddr:" << xAddr.toString();
        addr = xAddr;
#warning only get first val we only need one addr
    }

    // Probably should just qobject this. Hardly worth the threading.
    m_futures << QtConcurrent::run([=] {
        PBSDResolver resolver(addr, matchedService->endpointReference());
        auto discovery = resolver.run();
        emit newDiscovery(Discovery::Ptr(discovery));
    });
}
