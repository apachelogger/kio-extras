/* Copyright (C) 2019 Casper Meijn <casper@meijn.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "soapudpclient.h"

//TODO: Remove dependency for KDSoap internals
#include <src/KDSoapClient/KDSoapMessageReader_p.h>
#include <src/KDSoapClient/KDSoapMessageWriter_p.h>
#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QUdpSocket>
#include "loggingcategory.h"

SoapUdpClient::SoapUdpClient(QObject *parent) : QObject(parent)
{
    m_socketIPv4 = new QUdpSocket(this);
    connect(m_socketIPv4, &QUdpSocket::readyRead, this, &SoapUdpClient::readyRead);
    m_socketIPv6 = new QUdpSocket(this);
    connect(m_socketIPv6, &QUdpSocket::readyRead, this, &SoapUdpClient::readyRead);
}

bool SoapUdpClient::sendMessage(const KDSoapMessage& replyMessage, const KDSoapHeaders& replyHeaders, const QHostAddress &host, quint16 port)
{
    KDSoapMessageWriter msgWriter;
    msgWriter.setVersion(KDSoap::SOAP1_2);
    const QByteArray data = msgWriter.messageToXml(replyMessage, QString(), replyHeaders, QMap<QString, KDSoapMessage>());

    qCInfo(KDSoapWSDiscoveryClient) << "Sending out:" << data;

    if(host.protocol() == QAbstractSocket::IPv4Protocol) {
        qint64 writtenSize = m_socketIPv4->writeDatagram(QNetworkDatagram(data, host, port));
        return writtenSize == data.size();
    } else if(host.protocol() == QAbstractSocket::IPv6Protocol) {
        bool anySuccess = false;
        for (const auto &iface : QNetworkInterface::allInterfaces()) {
            // From qt docs: When using a link-local or site-local address for IPv6 connections, you must specify the scope ID.
            // We are using link-local as per the ws-discovery spec here.
            auto linkLocalHost = host;
            linkLocalHost.setScopeId(iface.name());
            qint64 writtenSize = m_socketIPv6->writeDatagram(QNetworkDatagram(data, linkLocalHost, port));
            anySuccess |= (writtenSize == data.size());
        }
        return anySuccess;
    }
    return false;
}

bool SoapUdpClient::bind(quint16 port, const QHostAddress& ipv4MulticastGroup, const QHostAddress& ipv6MulticastGroup)
{
    bool rc = true;
    rc = m_socketIPv4->bind(QHostAddress::AnyIPv4, port, QUdpSocket::ShareAddress) && rc;
    rc = m_socketIPv4->joinMulticastGroup(ipv4MulticastGroup) && rc;

    rc &= m_socketIPv6->bind(QHostAddress::AnyIPv6, port);
    for (const auto &iface : QNetworkInterface::allInterfaces()) {
        // From qt docs: Joining IPv6 multicast groups without an interface selection is not supported in all operating systems.
        rc &= m_socketIPv6->joinMulticastGroup(ipv6MulticastGroup, iface);
    }
    return rc;
}

void SoapUdpClient::readyRead()
{
    while (m_socketIPv4->hasPendingDatagrams()) {
        QNetworkDatagram datagram = m_socketIPv4->receiveDatagram();
        recievedDatagram(datagram);
    }
    while (m_socketIPv6->hasPendingDatagrams()) {
        QNetworkDatagram datagram = m_socketIPv6->receiveDatagram();
        recievedDatagram(datagram);
    }
}

void SoapUdpClient::recievedDatagram(const QNetworkDatagram &datagram)
{
    qCInfo(KDSoapWSDiscoveryClient) << "Recieved datagram from:" << datagram.senderAddress() << "data:" << QString::fromUtf8(datagram.data());

    KDSoapMessage replyMessage;
    KDSoapHeaders replyHeaders;

    KDSoapMessageReader reader;
    reader.xmlToMessage(datagram.data(), &replyMessage, 0, &replyHeaders, KDSoap::SOAP1_2);

    emit receivedMessage(replyMessage, replyHeaders, datagram.senderAddress(), datagram.senderPort());
}

