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

#include "dnssddiscoverer.h"
#include "kio_smb.h"

DNSSDDiscovery::DNSSDDiscovery(KDNSSD::RemoteService::Ptr service)
    : m_service(service)
{
}

void DNSSDDiscovery::toEntry(KIO::UDSEntry &entry)
{
    entry.fastInsert(KIO::UDSEntry::UDS_NAME, m_service->serviceName());

    entry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
    entry.fastInsert(KIO::UDSEntry::UDS_ACCESS, (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH));
    entry.fastInsert(KIO::UDSEntry::UDS_ICON_NAME, "network-server");
    entry.fastInsert(KIO::UDSEntry::UDS_ICON_OVERLAY_NAMES, "/home/me/avahi.png");

    // TODO: it may be better to resolve the host to an ip address. dnssd
    //   being able to find a service doesn't mean name resolution is
    //   properly set up for its domain. So, we may not be able to resolve
    //   this without help from avahi. OTOH KDNSSD doesn't have API for this
    //   and from a platform POV we should probably assume that if avahi
    //   is functional it is also set up as resolution provider.
    //   Given the plugin design on glibc's libnss however I am not sure
    //   that assumption will be true all the time. ~sitter, 2018
    QUrl u(QStringLiteral("smb://"));
    u.setHost(m_service->hostName());
    if (m_service->port() > 0 && m_service->port() != 445 /* default smb */) {
        u.setPort(m_service->port());
    }

    entry.fastInsert(KIO::UDSEntry::UDS_URL, u.url());
    entry.fastInsert(KIO::UDSEntry::UDS_MIME_TYPE,
                     QStringLiteral("application/x-smb-server"));
}

DNSSDDiscoverer::DNSSDDiscoverer()
{
    connect(&m_browser, &KDNSSD::ServiceBrowser::serviceAdded,
            this, [=](KDNSSD::RemoteService::Ptr service){
        qCDebug(KIO_SMB) << "DNSSD added:"
                         << service->serviceName()
                         << service->type()
                         << service->domain()
                         << service->hostName()
                         << service->port();
        // Manual contains check. We need to use the == of the underlying
        // objects, not the pointers. The same service may have >1
        // RemoteService* instances representing it, so the == impl of
        // RemoteService::Ptr is useless here.
        for (const auto &it : m_services) {
            if (*service == *it) {
                return;
            }
        }

        connect(service.data(), &KDNSSD::RemoteService::resolved,
                this, [=] {
            emit newDiscovery(Discovery::Ptr(new DNSSDDiscovery(service)));
        });

        // Schedule resolution of hostname. We'll later call resolve
        // which will block until the resolution is done. This basically
        // gives us a head start on discovery.
        service->resolveAsync();
        m_services.append(service);
    });
    connect(&m_browser, &KDNSSD::ServiceBrowser::finished,
            this, [=] {
        m_finished = true;
        emit finished();
    });
}

void DNSSDDiscoverer::start()
{
    m_browser.startBrowse();
}

void DNSSDDiscoverer::stop()
{
    m_browser.disconnect();
    for (auto service : m_services) {
        service->resolve(); // Blocks until resolution happened. Our signal handle then jumps in.
    }
}

bool DNSSDDiscoverer::isFinished()
{
    return m_finished;
}
