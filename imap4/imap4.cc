// $Id$
/**********************************************************************
 *
 *   imap4.cc  - IMAP4rev1 KIOSlave
 *   Copyright (C) 1999  John Corey
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   Send comments and bug fixes to jcorey@fruity.ath.cx
 *
 *********************************************************************/

/*
  References:
    RFC 2060 - Internet Message Access Protocol - Version 4rev1 - December 1996
    RFC 2192 - IMAP URL Scheme - September 1997
    RFC 1731 - IMAP Authentication Mechanisms - December 1994
               (Discusses KERBEROSv4, GSSAPI, and S/Key)
    RFC 2195 - IMAP/POP AUTHorize Extension for Simple Challenge/Response
             - September 1997 (CRAM-MD5 authentication method)
    RFC 2104 - HMAC: Keyed-Hashing for Message Authentication - February 1997

  Supported URLs:
    imap://server/ - Prompt for user/pass, list all folders in home directory
    imap://user:pass@server/ - Uses LOGIN to log in
    imap://user;AUTH=method:pass@server/ - Uses AUTHENTICATE to log in

    imap://server/folder/ - List messages in folder
 */

#include "imap4.h"

#include "rfcdecoder.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <fcntl.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <qbuffer.h>
#include <kprotocolmanager.h>
#include <ksock.h>
#include <kdebug.h>
#include <kinstance.h>
#include <kio/connection.h>
#include <kio/slaveinterface.h>
#include <kio/passdlg.h>
#include <klocale.h>

using namespace KIO;

FILE *myDebug;

extern "C"
{
  void sigalrm_handler (int);
  int kdemain (int argc, char **argv);
};

void
debugOut (FILE * myFile, const char *msg)
{
  fprintf (myFile, "%s\n", msg);
  fflush (myFile);
}

void
myHandler (QtMsgType type, const char *msg)
{
  if (&type);
  debugOut (myDebug, msg);
}

int
kdemain (int argc, char **argv)
{
  kdDebug(7116) << "IMAP4::kdemain" << endl;

  KInstance instance ("kio_imap4");
  if (argc != 4)
  {
    fprintf(stderr, "Usage: kio_imap4 protocol domain-socket1 domain-socket2\n");
    ::exit (-1);
  }

  //set debug handler
#ifdef EBUGGING
  myDebug = fopen ("/tmp/imap_slave", "a");
  fprintf (myDebug, "Debugging\n");
  fflush (myDebug);
  qInstallMsgHandler (myHandler);
#endif

  IMAP4Protocol *slave;
  if (strcasecmp (argv[1], "imaps") == 0)
    slave = new IMAP4Protocol (argv[2], argv[3], true);
  else if (strcasecmp (argv[1], "imap") == 0)
    slave = new IMAP4Protocol (argv[2], argv[3], false);
  else
    abort ();
  slave->dispatchLoop ();
  delete slave;

#ifdef EBUGGING
  fclose (myDebug);
#endif

  return 0;
}

void
sigchld_handler (int signo)
{
  int pid, status;

  while (true && signo == SIGCHLD)
  {
    pid = waitpid (-1, &status, WNOHANG);
    if (pid <= 0)
    {
      // Reinstall signal handler, since Linux resets to default after
      // the signal occured ( BSD handles it different, but it should do
      // no harm ).
      signal (SIGCHLD, sigchld_handler);
      return;
    }
  }
}

const QString hidePass(KURL aUrl)
{
  aUrl.setPass(QString::null);
  return KURL::decode_string(aUrl.url());
}

IMAP4Protocol::IMAP4Protocol (const QCString & pool, const QCString & app, bool isSSL):TCPSlaveBase ((isSSL ? 993 : 143), (isSSL ? "imap4-ssl" : "imap4"), pool,
              app), imapParser (),
mimeIO ()
{
  readBuffer[0] = 0x00;
  readSize = 0;
  relayEnabled = false;
}

IMAP4Protocol::~IMAP4Protocol ()
{
  CloseDescriptor();
  kdDebug(7116) << "IMAP4: Finishing" << endl;
}

void
IMAP4Protocol::get (const KURL & _url)
{
  kdDebug(7116) << "IMAP4::get -  " << _url.url () << endl;
  QString aBox, aSequence, aType, aSection, aValidity;
  enum IMAP_TYPE aEnum =
    parseURL (_url, aBox, aSection, aType, aSequence, aValidity);

  if (aSequence.isEmpty ())
  {
    aSequence = "1:*";
  }

  imapCommand *cmd = NULL;
  if (!assureBox (aBox, true))
  {
    error (ERR_COULD_NOT_READ, hidePass(_url));
    return;
  }

#ifdef USE_VALIDITY
  if (selectInfo.uidValidityAvailable () && !aValidity.isEmpty ()
      && selectInfo.uidValidity () != aValidity.toULong ())
  {
    // this url is stale
    error (ERR_COULD_NOT_READ, hidePass(_url));
  }
  else
#endif
  {
    if (aSection.find ("STRUCTURE", 0, false) != -1)
    {
      aSection = "BODYSTRUCTURE";
    }
    else if (aSection.find ("ENVELOPE", 0, false) != -1)
    {
      aSection = "ENVELOPE";
    }
    else
    {
      aSection = "BODY.PEEK[" + aSection + "]";
    }
    if (aEnum == ITYPE_BOX)
    {
      aSection += " RFC822.SIZE INTERNALDATE FLAGS";

      // write the digest header
      outputLine
        ("Content-Type: multipart/digest; boundary=\"IMAPDIGEST\"\r\n");
      if (selectInfo.recentAvailable ())
        outputLineStr ("X-Recent: " +
                       QString ().setNum (selectInfo.recent ()) + "\r\n");
      if (selectInfo.countAvailable ())
        outputLineStr ("X-Count: " + QString ().setNum (selectInfo.count ()) +
                       "\r\n");
      if (selectInfo.unseenAvailable ())
        outputLineStr ("X-Unseen: " +
                       QString ().setNum (selectInfo.unseen ()) + "\r\n");
      if (selectInfo.uidValidityAvailable ())
        outputLineStr ("X-uidValidity: " +
                       QString ().setNum (selectInfo.uidValidity ()) +
                       "\r\n");
      if (selectInfo.flagsAvailable ())
        outputLineStr ("X-Flags: " + QString ().setNum (selectInfo.flags ()) +
                       "\r\n");
      if (selectInfo.permanentFlagsAvailable ())
        outputLineStr ("X-PermanentFlags: " +
                       QString ().setNum (selectInfo.permanentFlags ()) +
                       "\r\n");
      if (selectInfo.readWriteAvailable ())
        outputLineStr (QString ("X-Access: ") +
                       (selectInfo.readWrite ()? "Read/Write" : "Read only") +
                       "\r\n");
      outputLine ("\r\n");
    }

    if (aEnum == ITYPE_MSG)
      relayEnabled = true;

    cmd = sendCommand (imapCommand::clientFetch (aSequence, aSection));
    do
    {
      while (!parseLoop ());

      mailHeader *lastone = NULL;
      imapCache *cache;
      cache = getLastHandled ();
      if (cache)
        lastone = cache->getHeader ();

      if (!cmd->isComplete ())
      {
        kdDebug(7116) << "IMAP4::get - got " << lastone << " from client" << endl;
        if (lastone && ((aSection.find ("BODYSTRUCTURE", 0, false) != -1)
                        || (aSection.find ("ENVELOPE", 0, false) != -1)
                        || (aSection.find ("BODY.PEEK[0]", 0, false) != -1
                            && aEnum == ITYPE_BOX)))
        {
          if (aEnum == ITYPE_BOX)
          {
            // write the mime header (default is here message/rfc822)
            outputLine ("--IMAPDIGEST\r\n");
            if (cache->getUid () != 0)
              outputLineStr ("X-UID: " +
                             QString ().setNum (cache->getUid ()) + "\r\n");
            if (cache->getSize () != 0)
              outputLineStr ("X-Length: " +
                             QString ().setNum (cache->getSize ()) + "\r\n");
            if (cache->getDate ()->tm_year != 0)
              outputLineStr ("X-Date: " + cache->getDateStr () + "\r\n");
            if (cache->getFlags () != 0)
              outputLineStr ("X-Flags: " +
                             QString ().setNum (cache->getFlags ()) + "\r\n");
            outputLine ("\r\n");
          }
          lastone->outputPart (*this);
        }
      }
    }
    while (!cmd->isComplete ());
    if (aEnum == ITYPE_BOX)
    {
      // write the end boundary
      outputLine ("--IMAPDIGEST--\r\n");
    }

    completeQueue.removeRef (cmd);
  }

  // just to keep everybody happy when no data arrived
  data (QByteArray ());

  finished ();
  relayEnabled = false;
  kdDebug(7116) << "IMAP4::get -  finished" << endl;
}

void
IMAP4Protocol::listDir (const KURL & _url)
{
  kdDebug(7116) << "IMAP4::listDir - " << _url.url () << endl;

  QString myBox, mySequence, myLType, mySection, myValidity;
  enum IMAP_TYPE myType =
    parseURL (_url, myBox, mySection, myLType, mySequence, myValidity);

  if (makeLogin () && myType == ITYPE_DIR)
  {
    QString listStr = myBox;
    imapCommand *cmd;

    if (!listStr.isEmpty ())
      listStr += "/";
    listStr += "%";
//    listResponses.clear();
    cmd =
      doCommand (imapCommand::clientList ("", listStr, myLType == "LSUB"));
    if (cmd->result () == "OK")
    {
      QString mailboxName;
      UDSEntry entry;
      UDSAtom atom;
      KURL aURL = _url;

      kdDebug(7116) << "IMAP4Protocol::listDir - got " << listResponses.count () << endl;

      for (QValueListIterator < imapList > it = listResponses.begin ();
           it != listResponses.end (); ++it)
        doListEntry (_url, myBox, (*it));
      entry.clear ();
      listEntry (entry, true);
    }
    else
    {
      error (ERR_CANNOT_ENTER_DIRECTORY, hidePass(_url));
    }
    completeQueue.removeRef (cmd);

  }
  else if (makeLogin () && myType == ITYPE_BOX)
  {
    if (!_url.query ().isEmpty ())
    {
      QString query = KURL::decode_string (_url.query ());
      query = query.right (query.length () - 1);
      if (!query.isEmpty ())
      {
        imapCommand *cmd = NULL;

        if (assureBox (myBox, true))
        {
          cmd = doCommand (imapCommand::clientSearch (query));
          completeQueue.removeRef (cmd);

          QStringList list = getResults ();
          int stretch = 0;

          if (selectInfo.uidNextAvailable ())
            stretch = QString ().setNum (selectInfo.uidNext ()).length ();
          UDSEntry entry;
          mailHeader *lastone = NULL;
          imapCache *cache;
          mailHeader fake;

//          kdDebug(7116) << "SEARCH returned - " << list.count() << endl;
          for (QStringList::Iterator it = list.begin (); it != list.end ();
               ++it)
          {
//            kdDebug(7116) << "SEARCH processing - " << (*it) << endl;

            // get the cached entry
            cache = getUid ((*it));
            if (cache)
              lastone = cache->getHeader ();
            else
              lastone = NULL;

            // if the uid is not in the cache we fake an entry
/*            if (!lastone)  Does not really work with the cache, Michael */
            {
//              kdDebug(7116) << "SEARCH faking - " << (*it) << endl;
              fake.setPartSpecifier ((*it));
              lastone = &fake;
            }
            doListEntry (_url, lastone, stretch);
          }
          entry.clear ();
          listEntry (entry, true);
        }
      }
    }
    else
    {

//      imapCommand *cmd = NULL;
      if (assureBox (myBox, true))
      {
        kdDebug(7116) << "IMAP4: select returned:" << endl;
        if (selectInfo.recentAvailable ())
          kdDebug(7116) << "Recent: " << selectInfo.recent () << "d" << endl;
        if (selectInfo.countAvailable ())
          kdDebug(7116) << "Count: " << selectInfo.count () << "d" << endl;
        if (selectInfo.unseenAvailable ())
          kdDebug(7116) << "Unseen: " << selectInfo.unseen () << "d" << endl;
        if (selectInfo.uidValidityAvailable ())
          kdDebug(7116) << "uidValidity: " << selectInfo.uidValidity () << "d" << endl;
        if (selectInfo.flagsAvailable ())
          kdDebug(7116) << "Flags: " << selectInfo.flags () << "d" << endl;
        if (selectInfo.permanentFlagsAvailable ())
          kdDebug(7116) << "PermanentFlags: " << selectInfo.permanentFlags () << "d" << endl;
        if (selectInfo.readWriteAvailable ())
          kdDebug(7116) << "Access: " << (selectInfo.readWrite ()? "Read/Write" : "Read only") << endl;

#ifdef USE_VALIDITY
        if (selectInfo.uidValidityAvailable ()
            && selectInfo.uidValidity () != myValidity.toULong ())
        {
          //redirect
          KURL newUrl = _url;

          newUrl.setPath ("/" + myBox + ";UIDVALIDITY=" +
                          QString ().setNum (selectInfo.uidValidity ()));
          kdDebug(7116) << "IMAP4::listDir - redirecting to " << newUrl.url () << endl;
          redirection (newUrl);


        }
        else
#endif
        if (selectInfo.count () > 0)
        {
          int stretch = 0;

          if (selectInfo.uidNextAvailable ())
            stretch = QString ().setNum (selectInfo.uidNext ()).length ();
          //        kdDebug(7116) << selectInfo.uidNext() << "d used to stretch " << stretch << endl;
          UDSEntry entry;

          if (mySequence.isEmpty ())
            mySequence = "1:*";
          imapCommand *fetch =
            sendCommand (imapCommand::
                         clientFetch (mySequence, "UID RFC822.SIZE"));
          do
          {
            while (!parseLoop ());

            mailHeader *lastone;
            imapCache *cache;
            cache = getLastHandled ();
            if (cache)
              lastone = cache->getHeader ();
            else
              lastone = NULL;

            if (!fetch->isComplete ())
            {
              doListEntry (_url, lastone, stretch);
            }
          }
          while (!fetch->isComplete ());
          entry.clear ();
          listEntry (entry, true);
        }
      }
      else
      {
        error (ERR_CANNOT_ENTER_DIRECTORY, hidePass(_url));
      }
//      completeQueue.removeRef(cmd);
    }
  }
  else
  {
    error (ERR_CANNOT_ENTER_DIRECTORY, hidePass(_url));
  }

  kdDebug(7116) << "IMAP4Protcol::listDir - Finishing listDir" << endl;
  finished ();
}

void
IMAP4Protocol::setHost (const QString & _host, int _port,
                        const QString & _user, const QString & _pass)
{
  kdDebug(7116) << "IMAP4::setHost - host= " << _host << ", port= " << _port << ", user= " << _user << ", pass=xx" << endl;

  if (myHost != _host || myPort != _port || myUser != _user)
  {
    if (!myHost.isEmpty ())
      closeConnection ();

    if (ConnectToHost (_host.ascii (), _port))
    {

      fcntl (m_iSock, F_SETFL, (fcntl (m_iSock, F_GETFL) | O_NDELAY));

//WORK      myState = ISTATE_CONNECT;
      myHost = _host;
      myUser = _user.left (_user.find (";AUTH=", 0, false));
      myPass = _pass;

      if (_user.find (";AUTH=", 0, false) != -1)
        myAuth =
          _user.right (_user.length () - _user.find (";AUTH=", 0, false) - 6);
      kdDebug(7116) << "IMAP4::setHost - host= " << _host << ", port= " << _port << ", user= " << _user << ", auth= " << myAuth << ", pass=xx" << endl;

      imapCommand *cmd;

      while (!parseLoop ());    //get greeting
      unhandled.clear ();       //get rid of it
      cmd = doCommand (new imapCommand ("CAPABILITY", ""));

      kdDebug(7116) << "IMAP4: setHost: capability" << endl;
      for (QStringList::Iterator it = imapCapabilities.begin ();
           it != imapCapabilities.end (); ++it)
      {
        kdDebug(7116) << "'" << (*it) << "'" << endl;
      }

      completeQueue.removeRef (cmd);
    }
    else
    {
      kdDebug(7116) << "IMAP4: setHost: ConnectToHost Failed!" << endl;
      myHost = QString::null;
      myUser = QString::null;
      myPass = QString::null;
      myAuth = QString::null;
    }
  }
  else
  {
    kdDebug(7116) << "IMAP4: setHost: reusing connection" << endl;
  }
//  parseLoop();
}

void
IMAP4Protocol::parseRelay (const QByteArray & buffer)
{
  if (relayEnabled)
    data (buffer);
}

void
IMAP4Protocol::parseRelay (ulong len)
{
  if (relayEnabled)
    totalSize (len);
}


void
IMAP4Protocol::parseReadLine (QByteArray & buffer, ulong relay)
{
  char buf[1024];
//  struct timeval m_tTimeout = {1, 0};
  fd_set FDs;
  ulong readLen;

  FD_ZERO (&FDs);
  FD_SET (m_iSock, &FDs);

  errno = 0;
  while (1)
  {
    memset (&buf, sizeof (buf), 0);
    if ((readLen = ReadLine (buf, sizeof (buf) - 1)) == 0)
    {
//        if (ferror(fp)) {
      //TODO: act on loss of connection
      if (buffer.isEmpty () || buffer[buffer.size () - 1] == '\n')
        break;
      /*        kdDebug(7116) << "IMAP4: Error while freading something[" << errno << "]: " << strerror(errno) << endl;
         return;
         } else {
         debug("IMAP4: Attempting select");
         while (::select(m_iSock+1, &FDs, 0, 0, &m_tTimeout) ==0) {
         debug("IMAP4: Sleeping");
         sleep(10);
         }
         debug("IMAP4: Finished select"); */
//        }  
    }
    else
    {
      if (relay > 0)
      {
        QByteArray relayData;

        if (readLen < relay)
          relay = readLen;
        relayData.setRawData (buf, relay);
        parseRelay (relayData);
        relayData.resetRawData (buf, relay);
        kdDebug(7116) << "relayed : " << relay << "d" << endl;
      }
      // append to buffer
      {
        QBuffer stream (buffer);

        stream.open (IO_WriteOnly);
        stream.at (buffer.size ());
        stream.writeBlock (buf, readLen);
        stream.close ();
//        kdDebug(7116) << "appended " << readLen << "d got now " << buffer.size() << endl;
      }
      if (buffer[buffer.size () - 1] != '\n')
        kdDebug(7116) << "************************** Partial filled buffer" << endl;
      else
        break;
    }
    sleep (1);
  }
}


void
IMAP4Protocol::mimetype (const KURL & _url)
{
  kdDebug(7116) << "IMAP4::mimetype - " << _url.url () << endl;
  QString aBox, aSequence, aType, aSection, aValidity;

  mimeType (getMimeType
            (parseURL (_url, aBox, aSection, aType, aSequence, aValidity)));
  finished ();
}

void
IMAP4Protocol::setSubURL (const KURL & _url)
{
  kdDebug(7116) << "IMAP4::setSubURL - " << _url.url () << endl;
  KIO::TCPSlaveBase::setSubURL (_url);
}

void
IMAP4Protocol::put (const KURL & _url, int, bool, bool)
{
  kdDebug(7116) << "IMAP4::put - " << _url.url () << endl;
//  KIO::TCPSlaveBase::put(_url,permissions,overwrite,resume);
  QString aBox, aSequence, aLType, aSection, aValidity;
  enum IMAP_TYPE aType =
    parseURL (_url, aBox, aSection, aLType, aSequence, aValidity);

  // see if it is a box
  if (aType != ITYPE_BOX)
  {
    if (aBox[aBox.length () - 1] == '/')
      aBox = aBox.right (aBox.length () - 1);
    imapCommand *cmd = doCommand (imapCommand::clientCreate (aBox));

    if (cmd->result () != "OK")
      error (ERR_COULD_NOT_WRITE, hidePass(_url));
    completeQueue.removeRef (cmd);
  }
  else
  {
    QList < QByteArray > bufferList;
    int length = 0;

    int result;
    // Loop until we got 'dataEnd'
    do
    {
      QByteArray *buffer = new QByteArray ();
      dataReq ();               // Request for data
      result = readData (*buffer);
      if (result > 0)
      {
        bufferList.append (buffer);
        length += result;
      }
    }
    while (result > 0);

    if (result != 0)
    {
      error (ERR_ABORTED, hidePass(_url));
      finished ();
      return;
    }

    imapCommand *cmd =
      sendCommand (imapCommand::clientAppend (aBox, "", length));
    while (!parseLoop ());

    // see if server is waiting
    if (!cmd->isComplete () && !getContinuation ().isEmpty ())
    {
      bool sendOk = true;
      ulong wrote = 0;

      QByteArray *buffer;
      while (!bufferList.isEmpty () && sendOk)
      {
        buffer = bufferList.take (0);

        sendOk =
          (Write (buffer->data (), buffer->size ()) ==
           (ssize_t) buffer->size ());
        wrote += buffer->size ();
        delete buffer;
        if (!sendOk)
        {
          error (ERR_CONNECTION_BROKEN, myHost);
        }
      }
      parseWriteLine ("");
      while (!cmd->isComplete ())
        parseLoop ();
      if (cmd->result () != "OK")
        error (ERR_COULD_NOT_WRITE, myHost);
      else
      {
        // MUST reselect to get the new message
        if (aBox == getCurrentBox ())
        {
          cmd =
            doCommand (imapCommand::
                       clientSelect (aBox, !selectInfo.readWrite ()));
          completeQueue.removeRef (cmd);
        }
      }
    }
    else
    {
      error (ERR_COULD_NOT_WRITE, myHost);
    }

    completeQueue.removeRef (cmd);
  }

  finished ();
}

void
IMAP4Protocol::mkdir (const KURL & _url, int)
{
  kdDebug(7116) << "IMAP4::mkdir - " << _url.url () << endl;
//  KIO::TCPSlaveBase::mkdir(_url,permissions);
  QString aBox, aSequence, aLType, aSection, aValidity;
  parseURL (_url, aBox, aSection, aLType, aSequence, aValidity);
  if (aBox[aBox.length () - 1] != '/')
    aBox += "/";
  imapCommand *cmd = doCommand (imapCommand::clientCreate (aBox));

  if (cmd->result () != "OK")
    error (ERR_COULD_NOT_MKDIR, hidePass(_url));

  completeQueue.removeRef (cmd);
  finished ();
}

void
IMAP4Protocol::copy (const KURL & src, const KURL & dest, int, bool overwrite)
{
  kdDebug(7116) << "IMAP4::copy - [" << (overwrite ? "Overwrite" : "NoOverwrite") << "] " << src.url () << " -> " << dest.url () << endl;
  QString sBox, sSequence, sLType, sSection, sValidity;
  QString dBox, dSequence, dLType, dSection, dValidity;
  enum IMAP_TYPE sType =
    parseURL (src, sBox, sSection, sLType, sSequence, sValidity);
  enum IMAP_TYPE dType =
    parseURL (dest, dBox, dSection, dLType, dSequence, dValidity);

  // see if we have to create anything
  if (dType != ITYPE_BOX)
  {
    // this might be konqueror
    int sub = dBox.find (sBox);

    // might be moving to upper folder
    if (sub > 0)
    {
      KURL testDir = dest;

      QString subDir = dBox.right (dBox.length () - dBox.findRev ("/"));
      QString topDir = dBox.left (sub);
      testDir.setPath ("/" + topDir);
      dType =
        parseURL (testDir, topDir, dSection, dLType, dSequence, dValidity);

      kdDebug(7116) << "IMAP4::copy - checking this destination " << topDir << endl;
      // see if this is what the user wants
      if (dType == ITYPE_BOX)
      {
        kdDebug(7116) << "IMAP4::copy - assuming this destination " << topDir << endl;
        dBox = topDir;
      }
      else
      {

        // maybe if we create a new mailbox
        topDir = "/" + topDir + subDir;
        testDir.setPath (topDir);
        kdDebug(7116) << "IMAP4::copy - checking this destination " << topDir << endl;
        dType =
          parseURL (testDir, topDir, dSection, dLType, dSequence, dValidity);
        if (dType != ITYPE_BOX)
        {
          // ok then we'll create a mailbox
          imapCommand *cmd = doCommand (imapCommand::clientCreate (topDir));

          // on success we'll use it, else we'll just try to create the given dir
          if (cmd->result () == "OK")
          {
            kdDebug(7116) << "IMAP4::copy - assuming this destination " << topDir << endl;
            dType = ITYPE_BOX;
            dBox = topDir;
          }
          else
          {
            completeQueue.removeRef (cmd);
            cmd = doCommand (imapCommand::clientCreate (dBox));
            if (cmd->result () == "OK")
              dType = ITYPE_BOX;
            else
              error (ERR_COULD_NOT_WRITE, hidePass(dest));
          }
          completeQueue.removeRef (cmd);
        }
      }

    }
  }
  if (sType == ITYPE_MSG)
  {
    //select the source box
    if (assureBox (sBox, true))
    {
      kdDebug(7116) << "IMAP4::copy - " << sBox << " -> " << dBox << endl;

      //issue copy command
      imapCommand *cmd =
        doCommand (imapCommand::clientCopy (dBox, sSequence));
      if (cmd->result () != "OK")
        error (ERR_COULD_NOT_WRITE, hidePass(dest));
      completeQueue.removeRef (cmd);

    }
    else
    {
      error (ERR_ACCESS_DENIED, hidePass(src));
    }
  }
  else
  {
    error (ERR_ACCESS_DENIED, hidePass(src));
  }
  finished ();
}

void
IMAP4Protocol::del (const KURL & _url, bool isFile)
{
  kdDebug(7116) << "IMAP4::del - [" << (isFile ? "File" : "NoFile") << "] " << _url.url () << endl;
  QString aBox, aSequence, aLType, aSection, aValidity;
  enum IMAP_TYPE aType =
    parseURL (_url, aBox, aSection, aLType, aSequence, aValidity);

  switch (aType)
  {
  case ITYPE_BOX:
    if (!aSequence.isEmpty ())
    {
      if (aSequence == "*")
      {
        if (assureBox (aBox, false))
        {
          imapCommand *cmd = doCommand (imapCommand::clientExpunge ());
          if (cmd->result () != "OK")
            error (ERR_CANNOT_DELETE, hidePass(_url));
          completeQueue.removeRef (cmd);
        }
        else error (ERR_CANNOT_DELETE, hidePass(_url));
      }
      else
      {
        // if open for read/write 
        if (assureBox (aBox, false))
        {
          imapCommand *cmd =
            doCommand (imapCommand::
                       clientStore (aSequence, "+FLAGS", "\\DELETED"));
          if (cmd->result () != "OK")
            error (ERR_CANNOT_DELETE, hidePass(_url));
          completeQueue.removeRef (cmd);
        }
        else
          error (ERR_CANNOT_DELETE, hidePass(_url));
      }
    }
    else
    {
      //TODO delete the mailbox
    }
    break;

  case ITYPE_DIR:
    {
      imapCommand *cmd = doCommand (imapCommand::clientDelete (aBox));
      if (cmd->result () != "OK")
        error (ERR_COULD_NOT_RMDIR, hidePass(_url));
      completeQueue.removeRef (cmd);
    }
    break;

  case ITYPE_MSG:
    {
      // if open for read/write 
      if (assureBox (aBox, false))
      {
        imapCommand *cmd =
          doCommand (imapCommand::
                     clientStore (aSequence, "+FLAGS", "\\DELETED"));
        if (cmd->result () != "OK")
          error (ERR_CANNOT_DELETE, hidePass(_url));
        completeQueue.removeRef (cmd);
      }
      else
        error (ERR_CANNOT_DELETE, hidePass(_url));
    }
    break;

  case ITYPE_UNKNOWN:
    error (ERR_CANNOT_DELETE, hidePass(_url));
    break;
  }
  finished ();
}

void
IMAP4Protocol::special (const QByteArray & data)
{
  KURL _url(data.data());
  QString aBox, aSequence, aLType, aSection, aValidity;
  parseURL (_url, aBox, aSection, aLType, aSequence, aValidity);
  if (assureBox (aBox, false))
  {
    imapCommand *cmd = doCommand (imapCommand::
      clientStore (aSequence, "-FLAGS",
      "\\SEEN \\ANSWERED \\FLAGGED \\DRAFT \\DELETED"));
    if (cmd->result () != "OK")
      error (ERR_NO_CONTENT, hidePass(_url));
    completeQueue.removeRef (cmd);
    cmd = doCommand (imapCommand::
      clientStore (aSequence, "+FLAGS", data.data() + data.find('\0') + 1));
    if (cmd->result () != "OK")
      error (ERR_NO_CONTENT, hidePass(_url));
    completeQueue.removeRef (cmd);
  }
  else error (ERR_CANNOT_OPEN_FOR_WRITING, hidePass(_url));
  finished();
}

void
IMAP4Protocol::rename (const KURL & src, const KURL & dest, bool overwrite)
{
  kdDebug(7116) << "IMAP4::rename - [" << (overwrite ? "Overwrite" : "NoOverwrite") << "] " << src.url () << " -> " << dest.url () << endl;
  QString sBox, sSequence, sLType, sSection, sValidity;
  QString dBox, dSequence, dLType, dSection, dValidity;
  enum IMAP_TYPE sType =
    parseURL (src, sBox, sSection, sLType, sSequence, sValidity);
  enum IMAP_TYPE dType =
    parseURL (dest, dBox, dSection, dLType, dSequence, dValidity);

  if (dType == ITYPE_UNKNOWN)
  {
    switch (sType)
    {
    case ITYPE_BOX:
    case ITYPE_DIR:
      {
        imapCommand *cmd = doCommand (imapCommand::clientRename (sBox, dBox));
        if (cmd->result () != "OK")
          error (ERR_CANNOT_RENAME, cmd->result ());
        completeQueue.removeRef (cmd);
      }
      break;

    case ITYPE_MSG:
    case ITYPE_UNKNOWN:
      error (ERR_CANNOT_RENAME, hidePass(src));
      break;
    }
  }
  else
  {
    error (ERR_CANNOT_RENAME, hidePass(src));
  }
  finished ();
}

void
IMAP4Protocol::slave_status ()
{
  kdDebug(7116) << "IMAP4::slave_status" << endl;
//  KIO::TCPSlaveBase::slave_status();
  slaveStatus (myHost, !(getState () == ISTATE_NO));
//  slaveStatus(QString::null,false);
}

void
IMAP4Protocol::dispatch (int command, const QByteArray & data)
{
  kdDebug(7116) << "IMAP4::dispatch - command=" << command << endl;
  KIO::TCPSlaveBase::dispatch (command, data);
}

void
IMAP4Protocol::stat (const KURL & _url)
{
  kdDebug(7116) << "IMAP4::stat - " << _url.url () << endl;
  QString aBox, aSequence, aLType, aSection, aValidity;
  enum IMAP_TYPE aType =
    parseURL (_url, aBox, aSection, aLType, aSequence, aValidity);

  if (aType == ITYPE_BOX || aType == ITYPE_MSG)
  {
    ulong validity = 0;
    // see if the box is already in select/examine state
    if (aBox == getCurrentBox ())
      validity = selectInfo.uidValidity ();
    else
    {
      // do a status lookup on the box
      // only do this if the box is not selected
      // the server might change the validity for new select/examine
      imapCommand *cmd =
        doCommand (imapCommand::clientStatus (aBox, "UIDVALIDITY"));
      completeQueue.removeRef (cmd);
      validity = getStatus ().uidValidity ();
    }
    validity = 0;               // temporary

    if (aType == ITYPE_BOX)
    {
      // has no or an invalid uidvalidity
      if (validity > 0 && validity != aValidity.toULong ())
      {
        //redirect
        KURL newUrl = _url;

        newUrl.setPath ("/" + aBox + ";UIDVALIDITY=" +
                        QString ().setNum (validity));
        kdDebug(7116) << "IMAP4::stat - redirecting to " << newUrl.url () << endl;
        redirection (newUrl);
      }
    }
    else if (aType == ITYPE_MSG)
    {
      //must determine if this message exists
      //cause konqueror will check this on paste operations

      // has an invalid uidvalidity
      // or no messages in box
      if (validity > 0 && validity != aValidity.toULong ())
      {
        aType = ITYPE_UNKNOWN;
        kdDebug(7116) << "IMAP4::stat - url has invalid validity [" << validity << "d] " << _url.url () << endl;
      }
    }
  }


  UDSEntry entry;
  UDSAtom atom;

  atom.m_uds = UDS_NAME;
  atom.m_str = aBox;
  entry.append (atom);

  atom.m_uds = UDS_MIME_TYPE;
  atom.m_str = getMimeType (aType);
  entry.append (atom);

  kdDebug(7116) << "IMAP4: stat: " << atom.m_str << endl;
  switch (aType)
  {
  case ITYPE_DIR:
    atom.m_uds = UDS_FILE_TYPE;
    atom.m_str = "";
    atom.m_long = S_IFDIR;
    entry.append (atom);
    break;

  case ITYPE_BOX:
    atom.m_uds = UDS_FILE_TYPE;
    atom.m_str = "";
    atom.m_long = S_IFDIR;
    entry.append (atom);
    break;

  case ITYPE_MSG:
    atom.m_uds = UDS_FILE_TYPE;
    atom.m_str = "";
    atom.m_long = S_IFREG;
    entry.append (atom);
    break;

  case ITYPE_UNKNOWN:
    error (ERR_DOES_NOT_EXIST, hidePass(_url));
    break;
  }



  statEntry (entry);
  kdDebug(7116) << "IMAP4::stat - Finishing stat" << endl;
  finished ();
}

void IMAP4Protocol::openConnection()
{
  if (makeLogin()) connected();
}

bool IMAP4Protocol::makeLogin ()
{
  bool skipFirst = true;

  kdDebug(7116) << "IMAP4::makeLogin - checking login" << endl;
  if (getState () == ISTATE_LOGIN || getState () == ISTATE_SELECT)
    return true;

  if (!myAuth.isEmpty () && myAuth != "*"
      && !hasCapability (QString ("AUTH=") + myAuth))
  {
    error (ERR_UNSUPPORTED_PROTOCOL, myAuth);
    return false;
  }

  kdDebug(7116) << "IMAP4::makeLogin - attempting login" << endl;

  if (myUser.isEmpty () || myPass.isEmpty ())
    skipFirst = false;

  while (skipFirst
         ||
         openPassDlg (i18n ("Username and password for your IMAP account:"),
                      myUser, myPass))
  {

    kdDebug(7116) << "IMAP4::makeLogin - open_PassDlg: user=" << myUser << " pass=xx" << endl;
    skipFirst = false;

    if (myAuth.isEmpty () || myAuth == "*")
    {
      if (clientLogin (myUser, myPass))
      {
        kdDebug(7116) << "IMAP4::makeLogin - login succeded" << endl;
      }
      else
        kdDebug(7116) << "IMAP4::makeLogin - login failed" << endl;
    }
    else
    {
      if (clientAuthenticate (myUser, myPass, myAuth))
      {
        kdDebug(7116) << "IMAP4::makeLogin: " << myAuth << " succeded" << endl;
      }
      else
        kdDebug(7116) << "IMAP4::makeLogin: " << myAuth << " failed" << endl;
    }
    if (getState () == ISTATE_LOGIN)
      break;
  }



  if (getState () == ISTATE_LOGIN)
    return true;

  return false;
}

void
IMAP4Protocol::parseWriteLine (const QString & aStr)
{
  QCString writer = aStr.utf8 ();

  // append CRLF if necessary
  if (writer[writer.length () - 1] != '\n')
    writer += "\r\n";

  // write it
  Write (writer.data (), writer.length ());
}

QString
IMAP4Protocol::getMimeType (enum IMAP_TYPE aType)
{
  QString retVal = "unknown/unknown";

  switch (aType)
  {
  case ITYPE_UNKNOWN:
    retVal = "unknown/unknown";
    break;

  case ITYPE_DIR:
    retVal = "inode/directory";
    break;

  case ITYPE_BOX:
    retVal = "message/digest";
    break;

  case ITYPE_MSG:
    retVal = "message/rfc822-imap";
    break;
  }

  return retVal;
}



void
IMAP4Protocol::doListEntry (const KURL & _url, mailHeader * what, int stretch)
{
  if (what)
  {
    UDSEntry entry;
    UDSAtom atom;
    KURL aURL = _url;
    aURL.setQuery (QString::null);

    entry.clear ();

    atom.m_uds = UDS_NAME;
    atom.m_str = what->getPartSpecifier ();
    atom.m_long = 0;
    if (stretch > 0)
    {
      atom.m_str = "0000000000000000" + atom.m_str;
      atom.m_str = atom.m_str.right (stretch);
    }
//    atom.m_str.prepend(";UID=");
    entry.append (atom);

    atom.m_uds = UDS_URL;
    atom.m_str = aURL.url ();
    if (atom.m_str[atom.m_str.length () - 1] != '/')
      atom.m_str += "/";
    atom.m_str += ";UID=" + what->getPartSpecifier ();
    atom.m_long = 0;
    entry.append (atom);

    atom.m_uds = UDS_FILE_TYPE;
    atom.m_str = "";
    atom.m_long = S_IFREG;
    entry.append (atom);

    atom.m_uds = UDS_SIZE;
    atom.m_long = what->getLength ();
    entry.append (atom);
    atom.m_uds = UDS_MIME_TYPE;
    atom.m_str = "message/rfc822-imap";
    atom.m_long = 0;
    entry.append (atom);

    atom.m_uds = UDS_USER;
    atom.m_str = myUser;
    entry.append (atom);

    atom.m_uds = KIO::UDS_ACCESS;
    atom.m_long = S_IRUSR | S_IXUSR | S_IWUSR;
    entry.append (atom);

    listEntry (entry, false);
  }
}

void
IMAP4Protocol::doListEntry (const KURL & _url, const QString & myBox,
                            const imapList & item)
{
  KURL aURL = _url;
  aURL.setQuery (QString::null);
  UDSEntry entry;
  UDSAtom atom;

  {
    QString mailboxName = item.name ();

    // some beautification
    if (mailboxName.find (myBox) == 0)
    {
      mailboxName =
        mailboxName.right (mailboxName.length () - myBox.length ());
    }
    if (mailboxName[0] == '/')
      mailboxName = mailboxName.right (mailboxName.length () - 1);

    atom.m_uds = UDS_NAME;
    atom.m_str = mailboxName;

    // konqueror will die with an assertion failure otherwise
    if (atom.m_str.isEmpty ())
      atom.m_str = "..";

    if (!atom.m_str.isEmpty ())
    {
      atom.m_long = 0;
      entry.append (atom);


      if (!item.noSelect ())
      {
        atom.m_uds = UDS_MIME_TYPE;
        atom.m_str = "message/digest";
        atom.m_long = 0;
        entry.append (atom);
        mailboxName += "/";
      }
      else if (!item.noInferiors ())
      {
        atom.m_uds = UDS_MIME_TYPE;
        atom.m_str = "inode/directory";
        atom.m_long = 0;
        entry.append (atom);
        mailboxName += "/";
      }
      else
      {
        atom.m_uds = UDS_MIME_TYPE;
        atom.m_str = "unknown/unknown";
        atom.m_long = 0;
        entry.append (atom);
      }

      atom.m_uds = UDS_URL;
      atom.m_str = aURL.url ();
      if (atom.m_str[atom.m_str.length () - 1] != '/')
        atom.m_str += "/";
      atom.m_str += mailboxName;
      atom.m_long = 0;
      entry.append (atom);

      atom.m_uds = UDS_USER;
      atom.m_str = myUser;
      entry.append (atom);

      atom.m_uds = KIO::UDS_ACCESS;
      atom.m_long = S_IRUSR | S_IXUSR | S_IWUSR;
      entry.append (atom);

      listEntry (entry, false);
    }
  }
}

enum IMAP_TYPE
IMAP4Protocol::parseURL (const KURL & _url, QString & _box,
                         QString & _section, QString & _type, QString & _uid,
                         QString & _validity)
{
//  kdDebug(7116) << "IMAP4::parseURL - " << _url.url() << endl;
  enum IMAP_TYPE retVal;
  retVal = ITYPE_UNKNOWN;

  imapParser::parseURL (_url, _box, _section, _type, _uid, _validity);
//  kdDebug(7116) << "URL: query - '" << KURL::decode_string(_url.query()) << "'" << endl;

  if (!_box.isEmpty ())
  {
//     kdDebug(7116) << "IMAP4::parseURL: box " << _box << endl;

    if (makeLogin ())
    {
      if (getCurrentBox () != _box)
      {
        imapCommand *cmd;

        cmd = doCommand (imapCommand::clientList ("", _box));
        if (cmd->result () == "OK")
        {
          for (QValueListIterator < imapList > it = listResponses.begin ();
               it != listResponses.end (); ++it)
          {
//            kdDebug(7116) << "IMAP4::parseURL - checking " << _box << " to " << (*it).name() << endl;
            if (_box == (*it).name ())
            {
              if ((*it).noSelect ())
              {
                retVal = ITYPE_DIR;
              }
              else
              {
                retVal = ITYPE_BOX;
              }
            }
          }
        }
        completeQueue.removeRef (cmd);
      }
      else
      {
        retVal = ITYPE_BOX;
      }
    }
    else
      kdDebug(7116) << "IMAP4::parseURL: no login!" << endl;

  }
  else
  {
    kdDebug(7116) << "IMAP4: parseURL: box [root]" << endl;
    retVal = ITYPE_DIR;
  }

  //see if it is a real sequence or a simple uid
  if (retVal == ITYPE_BOX)
  {
    if (!_uid.isEmpty ())
    {
      if (_uid.find (":") == -1 && _uid.find (",") == -1
          && _uid.find ("*") == -1)
        retVal = ITYPE_MSG;
    }
  }
  switch (retVal)
  {
  case ITYPE_DIR:
    kdDebug(7116) << "IMAP4::parseURL: dir" << endl;
    break;

  case ITYPE_BOX:
    kdDebug(7116) << "IMAP4::parseURL: box" << endl;
    break;

  case ITYPE_MSG:
    kdDebug(7116) << "IMAP4::parseURL: msg" << endl;
    break;

  case ITYPE_UNKNOWN:
    kdDebug(7116) << "IMAP4::parseURL: unknown" << endl;
    break;
  }
  kdDebug(7116) << "URL: box= " << _box << ", section= " << _section << ", type= " << _type << ", uid= " << _uid << ", validity= " << _validity << endl;

  return retVal;
}

int
IMAP4Protocol::outputLine (const QCString & _str)
{
  QByteArray temp;
  bool relay = relayEnabled;

  relayEnabled = true;
  temp.setRawData (_str.data (), _str.length ());
  parseRelay (temp);
  temp.resetRawData (_str.data (), _str.length ());

  relayEnabled = relay;
  return 0;
}

/* memccpy appeared first in BSD4.4 */
void *
mymemccpy (void *dest, const void *src, int c, size_t n)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  while (n-- > 0)
    if ((*d++ = *s++) == c)
      return d;

  return NULL;
}

ssize_t
IMAP4Protocol::ReadLine (char *buf, ssize_t len)
{
  ssize_t result;
  char *copied;
//  kdDebug(7116) << "Request for " << len << endl;
  // see what is still in the buffer
  if (len > readSize)
  {
//    kdDebug(7116) << "Reading" << endl;
    // append to our internal buffer
    result = Read (readBuffer + readSize, IMAP_BUFFER - readSize);
    if (result > 0)
      readSize += result;
//    kdDebug(7116) << "Result is " << result << endl;
//    kdDebug(7116) << "Now got " << readSize << endl;
  }

  // give what is there to the caller
  if (readSize < len)
    len = readSize;

  if (len > 0)
  {
    // copy it to the destination
//    kdDebug(7116) << "Giving to caller at most " << len << endl;
    copied = (char *) mymemccpy (buf, readBuffer, '\n', len);
    if (copied)
      len = copied - buf;
//    kdDebug(7116) << "Copied " << len << endl;
    buf[len] = 0x00;
//    kdDebug(7116) << "Giving to caller " << len << endl;
//    kdDebug(7116) << "That is '" << buf << "'" << endl;

    // now we need to readjust our buffer
    memcpy (readBuffer, readBuffer + len, readSize - len);
    readSize -= len;
    readBuffer[readSize] = 0x00;
//    kdDebug(7116) << "Keeping " << readSize << " [" << readBuffer << "]" << endl;
  }

  if (len <= 0)
    len = 0;
  return len;
}

bool
IMAP4Protocol::assureBox (const QString & aBox, bool readonly)
{
  imapCommand *cmd = NULL;

  if (aBox != getCurrentBox ())
  {
    // open the box with the appropriate mode
    kdDebug(7116) << "IMAP4Protocol::assureBox - opening box" << endl;
    cmd = doCommand (imapCommand::clientSelect (aBox, readonly));
    completeQueue.removeRef (cmd);
  }
  else
  {
    // check if it is the mode we want
    if (getSelected ().readWrite () || readonly)
    {
      // give the server a chance to deliver updates
      kdDebug(7116) << "IMAP4Protocol::assureBox - reusing box" << endl;
      cmd = doCommand (imapCommand::clientNoop ());
      completeQueue.removeRef (cmd);
    }
    else
    {
      // reopen the box with the appropriate mode
      kdDebug(7116) << "IMAP4Protocol::assureBox - reopening box" << endl;
      cmd = doCommand (imapCommand::clientSelect (aBox, readonly));
      completeQueue.removeRef (cmd);
    }
  }

  // if it isn't opened
  if (aBox != getCurrentBox ())
    return false;

  // if it is the mode we want
  if (getSelected ().readWrite () || readonly)
    return true;

  // we goofed somewhere
  return false;
}
