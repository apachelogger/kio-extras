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

#ifndef WSDISCOVERER_H
#define WSDISCOVERER_H

#include <QObject>
#include <QTimer>
#include <QFuture>
#include "discovery.h"

class WSDiscoveryClient;
class WSDiscoveryProbeJob;
class WSDiscoveryTargetService;
class PBSDResolver;

#include <kio/udsentry.h>
#include <QUrl>

class WSDiscovery : public Discovery
{
    const QString m_computer;
    const QString m_remote;

public:
    WSDiscovery(const QString &computer, const QString &remote)
        : m_computer(computer)
        , m_remote(remote)
    {
    }

    void toEntry(KIO::UDSEntry &entry) override
    {
        entry.fastInsert(KIO::UDSEntry::UDS_NAME, m_computer);

        entry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
        entry.fastInsert(KIO::UDSEntry::UDS_ACCESS, (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH));
        entry.fastInsert(KIO::UDSEntry::UDS_ICON_NAME, "network-server");
        entry.fastInsert(KIO::UDSEntry::UDS_ICON_OVERLAY_NAMES, "/home/me/.local/share/icons/Windows10Icons/32x32/places/ubuntu-logo.png");

        QUrl u(QStringLiteral("smb://"));
        u.setHost(m_remote);

        entry.fastInsert(KIO::UDSEntry::UDS_URL, u.url());
        entry.fastInsert(KIO::UDSEntry::UDS_MIME_TYPE,
                            QStringLiteral("application/x-smb-server"));
    }
};

class WSDiscoverer : public QObject, public virtual Discoverer
{
    Q_OBJECT
public:
    WSDiscoverer();

    void start() override;
    void stop() override;
    bool isFinished() override;

signals:
    void newDiscovery(Discovery::Ptr discovery) override;
    void finished() override;

private slots:
    void matchReceived(const QSharedPointer<WSDiscoveryTargetService> &matchedService);

private:
    WSDiscoveryClient * m_client = nullptr;
    WSDiscoveryProbeJob * m_probeJob = nullptr;
    bool m_startedTimer = false;
    QTimer m_probeMatchTimer;
    QList<QFuture<void>> m_futures;
    QStringList m_seenEndpoints;
};

#endif // WSDISCOVERER_H
