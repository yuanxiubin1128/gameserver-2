/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Simon Sandström
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <functional>
#include <memory>
#include <boost/asio.hpp>  //NOLINT

#include "configparser.h"
#include "logger.h"
#include "account.h"
#include "server.h"
#include "incomingpacket.h"
#include "outgoingpacket.h"
#include "rsa.h"

void onClientConnected(ConnectionId connectionId);
void onClientDisconnected(ConnectionId connectionId);
void onPacketReceived(ConnectionId connectionId, IncomingPacket* packet);
void parseLogin(ConnectionId connectionId, IncomingPacket* packet);

int version;
AccountReader accountReader;
std::unique_ptr<Server> server;
std::string motd;
RSA rsa;

void onClientConnected(ConnectionId connectionId)
{
  LOG_DEBUG("Client connected, id: %d", connectionId);
}

void onClientDisconnected(ConnectionId connectionId)
{
  LOG_DEBUG("Client disconnected, id: %d", connectionId);
}

void onPacketReceived(ConnectionId connectionId, IncomingPacket* packet)
{
  LOG_DEBUG("Parsing packet from connection id: %d", connectionId);

  while (!packet->isEmpty())
  {
    uint8_t packetId = packet->getU8();
    switch (packetId)
    {
      case 0x01:
      {
        parseLogin(connectionId, packet);
        break;
      }

      default:
      {
        LOG_DEBUG("Unknown packet from connection id: %d, packet id: %d", connectionId, packetId);
        server->closeConnection(connectionId);
        break;
      }
    }
  }
}

void parseLogin(ConnectionId connectionId, IncomingPacket* packet)
{
  LOG_DEBUG("Parsing login packet from connection id: %d", connectionId);

  auto clientOs = packet->getU16();       // Client OS
  auto clientVersion = packet->getU16();  // Client version
  packet->getBytes(12);                       // Client OS info

  if (version == 772)
  {
    if (packet->bytesLeft() != 128)
    {
      LOG_ERROR("Can't decrypt packet, size should be 128, not %u", packet->bytesLeft());
      return;
    }

    // Decrypt RSA
    rsa.decrypt(&(packet->getBuffer()[1 + 2 + 2 + 12]));
    if (packet->getU8() != 0x00)
    {
      LOG_ERROR("Could not decrypt packet!");
      return;
    }

    std::array<uint32_t, 4> xteaKey;
    xteaKey[0] = packet->getU32();
    xteaKey[1] = packet->getU32();
    xteaKey[2] = packet->getU32();
    xteaKey[3] = packet->getU32();

    LOG_DEBUG("xteaKey = { %u, %u, %u, %u }", xteaKey[0], xteaKey[1], xteaKey[2], xteaKey[3]);
  }

  auto accountNumber = packet->getU32();
  auto password = packet->getString();

  LOG_DEBUG("Client OS: %d Client version: %d Account number: %d Password: %s",
            clientOs,
            clientVersion,
            accountNumber,
            password.c_str());

  // We need XTEA to reply, quit here
  packet->getBytes(packet->bytesLeft());
  return;

  // Send outgoing packet
  OutgoingPacket response;

    // Add MOTD
  response.addU8(0x14);  // MOTD
  response.addString("0\n" + motd);

  // Check if account exists
  if (!accountReader.accountExists(accountNumber))
  {
    LOG_DEBUG("%s: Account (%d) not found", __func__, accountNumber);
    response.addU8(0x0A);
    response.addString("Invalid account number");
  }
  // Check if password is correct
  else if (!accountReader.verifyPassword(accountNumber, password))
  {
    LOG_DEBUG("%s: Invalid password (%s) for account (%d)", __func__, password.c_str(), accountNumber);
    response.addU8(0x0A);
    response.addString("Invalid password");
  }
  else
  {
    const auto* account = accountReader.getAccount(accountNumber);
    LOG_DEBUG("%s: Account number (%d) and password (%s) OK", __func__, accountNumber, password.c_str());
    response.addU8(0x64);
    response.addU8(account->characters.size());
    for (const auto& character : account->characters)
    {
      response.addString(character.name);
      response.addString(character.worldName);
      response.addU32(character.worldIp);
      response.addU16(character.worldPort);
    }
    response.addU16(account->premiumDays);
  }

  LOG_DEBUG("Sending login response to connection_id: %d", connectionId);
  server->sendPacket(connectionId, response);

  LOG_DEBUG("Closing connection id: %d", connectionId);
  server->closeConnection(connectionId);
}

int main(int argc, char* argv[])
{
  // Read configuration
  auto config = ConfigParser::parseFile("data/loginserver.cfg");
  if (!config.parsedOk())
  {
    LOG_INFO("Could not parse config file: %s", config.getErrorMessage().c_str());
    LOG_INFO("Will continue with default values");
  }

  version = config.getInteger("server", "version", 772);
  auto serverPort = config.getInteger("server", "port", 7171);

  motd = config.getString("login", "motd", "Welcome to LoginServer!");
  auto accountsFilename = config.getString("login", "accounts_file", "data/accounts.xml");

  // Print configuration values
  LOG_INFO("                            LoginServer configuration                           ");
  LOG_INFO("================================================================================");
  LOG_INFO("Version:                   %d", version);
  LOG_INFO("Server port:               %d", serverPort);
  LOG_INFO("");
  LOG_INFO("Message of the day:        %s", motd.c_str());
  LOG_INFO("Accounts filename:         %s", accountsFilename.c_str());
  LOG_INFO("================================================================================");

  // Setup io_service, AccountManager and Server
  boost::asio::io_service io_service;

  boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
  signals.async_wait(std::bind(&boost::asio::io_service::stop, &io_service));

  if (!accountReader.loadFile(accountsFilename))
  {
    LOG_ERROR("Could not load accounts file: %s", accountsFilename.c_str());
    return 1;
  }

  Server::Callbacks callbacks =
  {
    &onClientConnected,
    &onClientDisconnected,
    &onPacketReceived,
  };
  server = std::unique_ptr<Server>(new Server(&io_service, serverPort, callbacks));

  // Start Server and io_service
  if (!server->start())
  {
    LOG_ERROR("Could not start Server");
    return 1;
  }

  // run() will continue to run until ^C from user is catched
  io_service.run();

  LOG_INFO("Stopping server");
  server->stop();

  return 0;
}
