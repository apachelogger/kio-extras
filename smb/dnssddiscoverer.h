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

#ifndef DNSSDDISCOVERER_H
#define DNSSDDISCOVERER_H

#include <QObject>

#include <DNSSD/ServiceBrowser>
#include <DNSSD/RemoteService>

#include "discovery.h"

class DNSSDDiscovery : public Discovery
{
public:
    DNSSDDiscovery(KDNSSD::RemoteService::Ptr service);
    void toEntry(KIO::UDSEntry &entry) override;

private:
    KDNSSD::RemoteService::Ptr m_service;
};

class DNSSDDiscoverer : public QObject, public virtual Discoverer
{
    Q_OBJECT
public:
    DNSSDDiscoverer();

    void start() override;
    void stop() override;
    bool isFinished() override;

signals:
    void newDiscovery(Discovery::Ptr discovery) override;
    void finished() override;

private:
    KDNSSD::ServiceBrowser m_browser { QStringLiteral("_smb._tcp") };
    QList<KDNSSD::RemoteService::Ptr> m_services;
    bool m_finished = false;
};

#endif // DNSSDDISCOVERER_H
