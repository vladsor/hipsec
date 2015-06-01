{-# LANGUAGE DeriveDataTypeable, FlexibleContexts #-}
module Main (main) where

import PFKey
import Message
import System.Console.CmdArgs
import Control.Monad
import Data.DateTime
import qualified Data.ByteString.Lazy as LBS
--import qualified Data.ByteString.Char8 as BS
import System.IO (stdin)
import Data.Binary (encode, decode)
import Control.Applicative
import qualified Text.Parsec as P
import qualified Text.Parsec.Prim as P
import Network.Socket
import Data.Bits
import Data.Char

data SetKey = SetKey { dump :: Bool
                     , flush :: Bool
                     , policy :: Bool
                     , cmds :: Bool
                     } deriving (Show, Data, Typeable)

setkey = SetKey
               {dump = def &= name "D"  &= help 
                       "Dump the SAD entries.  If -P is also specified, the SPD entries are dumped.  If -p is specified, the ports are displayed."
               ,flush = def &= name "F" &= help 
                        "Flush the SAD entries.  If -P is also specified, the SPD entries are flushed."
               ,policy = def &= name "P" &= help "Policy entries"
               ,cmds = def &= name "c" &= help "read commands from stdin"
               }
              &=
    verbosity &=
    help "" &=
    summary "F-IPSec-Tools v0.0.0, (C) Vladimir Sorokin 2011" &=
    details ["",""
            ,"",""] 

main :: IO ()
main = do
  opts <- cmdArgs setkey
  
  case policy opts of
    True -> do
      when (dump opts) $ do
        s <- pfkey_open
        pfkey_send_spddump s
        iterateM_ $ do
          res <- pfkey_recv s 
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              pfkey_spd_dump msg
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
        pfkey_close s
      return () 
      when (flush opts) $ do
        putStrLn "SPD Flush"
        s <- pfkey_open
        pfkey_send_spdflush s
        pfkey_close s
    False -> do
      when (dump opts) $ do
        s <- pfkey_open
        pfkey_send_dump s SATypeUnspec
        iterateM_ $ do
          res <- pfkey_recv s 
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              ct <- getCurrentTime
              putStrLn $ pfkey_sa_dump msg ct
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
        pfkey_close s
      when (flush opts) $ do
        putStrLn "SAD Flush"
        s <- pfkey_open
--        pfkey_send_flush s SATypeUnspec
        doCommand s CommandFlush
        pfkey_close s
  
  when (cmds opts) $ do
    putStrLn "Read commands"
    raw <- getContents
    case (P.parse tokenize "" raw) of
      Left err -> print err
      Right xs -> do
        print xs
        let xs' = filter (\i -> case i of 
              TokenComment _ -> False
              _ -> True) xs
        case (P.parse parser "" xs') of
          Left err' -> print err'
          Right cmds -> do
            print cmds
            s <- pfkey_open
            mapM_ (doCommand s) cmds
            pfkey_close s

doCommand :: Socket -> Command -> IO ()
doCommand s CommandFlush = pfkey_send_flush s SATypeUnspec
doCommand s CommandDump = do
        pfkey_send_dump s SATypeUnspec
        iterateM_ $ do
          res <- pfkey_recv s 
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              ct <- getCurrentTime
              putStrLn $ pfkey_sa_dump msg ct
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s CommandSPDFlush = pfkey_send_flush s SATypeUnspec
doCommand s CommandSPDDump = do
        pfkey_send_spddump s
        iterateM_ $ do
          res <- pfkey_recv s 
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              pfkey_spd_dump msg
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
{-
doCommand s (CommandAdd src dst proto spi encAlg encKey authAlg authKey compAlg) = undefined
                          }
             | CommandGet { getSrc :: String
                          , getDst :: String
                          , getProto :: String
                          , getSPI :: String
                          }
             | CommandDelete { deleteSrc :: String
                             , deleteDst :: String
                             , deleteProto :: String
                             , deleteSPI :: String
                             }
             | CommandDeleteAll { deleteAllSrc :: String
                                , deleteAllDst :: String
                                , deleteAllProto :: String
                                }
-}
doCommand s (CommandSPDAdd (Address sproto prefs src) (Address droto prefd dst) upper label policy) = do
  pfkey_send_spdadd s src prefs dst prefd (fromIntegral $ packIPProto upper) policy 0

{-
             | CommandSPDAddTagged { spdAddTaggedTag :: String
                                   , spdAddTaggedPolicy :: String
                                   }
             | CommandSPDDelete { spdDeleteSrcRange :: String
                                , spdDeleteDstRange :: String
                                , spdDeleteUppperspec :: String
                                , spdDeleteDirection :: String
                                }
-}
doCommand _ _ = error "doCommand error"

data Token = Token { tknString :: String } 
           | TokenNumber { tknNumber :: Int }
           | TokenEOC 
           | TokenSlash
           | TokenSqBrOpen
           | TokenSqBrClose
           | TokenDot
           | TokenComment { tknComment :: String }
           deriving (Eq, Show)
                    
separator = P.many1 (P.oneOf " \t\n")
tokenize = P.many $ do 
  P.optionMaybe separator
  tkn <- P.choice [ P.char ';' >> return TokenEOC
                  , P.char '#' >> P.many (P.noneOf "\n") >>= return . TokenComment
                  , P.char '-' >> return (Token "-")
                  , P.char '/' >> return TokenSlash
                  , P.char '[' >> return TokenSqBrOpen
                  , P.char ']' >> return TokenSqBrClose
                  , P.char '.' >> return TokenDot
                  , P.many1 P.digit >>= return . TokenNumber . (foldl (\a b -> a * 10 + digitToInt b) 0)  
                  , P.many1 (P.noneOf " \t\n;#-/[].") >>= return . Token 
                  ]
  P.optionMaybe separator
  return tkn

satisfy :: P.Stream s m Token => (Token -> Bool) -> P.ParsecT s u m Token
satisfy f = P.tokenPrim (\c -> show c) (\pos _c _cs -> P.incSourceColumn pos 1)
                      (\c -> if f c then Just c else Nothing)

token :: P.Stream s m Token => String -> P.ParsecT s u m String
token str = (satisfy ( == (Token str))) >>= return . tknString

tokenString :: P.Stream s m Token => P.ParsecT s u m String
tokenString = (satisfy f) >>= return . tknString
  where
    f (Token _) = True
    f _ = False

tokenNumber :: P.Stream s m Token => P.ParsecT s u m Int
tokenNumber = (satisfy f) >>= return . tknNumber
  where
    f (TokenNumber _) = True
    f _ = False

tokenEOC :: P.Stream s m Token => P.ParsecT s u m ()
tokenEOC = (satisfy (== TokenEOC)) >> return ()

tokenSlash :: P.Stream s m Token => P.ParsecT s u m String
tokenSlash = (satisfy f) >>= return . tknString
  where
    f TokenSlash = True
    f _ = False

tokenSqBrOpen :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrOpen = (satisfy f) >> return ()
  where
    f TokenSqBrOpen = True
    f _ = False

tokenSqBrClose :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrClose = (satisfy f) >> return ()
  where
    f TokenSqBrClose = True
    f _ = False

tokenDot :: P.Stream s m Token => P.ParsecT s u m ()
tokenDot = (satisfy f) >> return ()
  where
    f TokenDot = True
    f _ = False

cmdFlush :: P.Stream s m Token => P.ParsecT s u m Command
cmdFlush = token "flush" >> return CommandFlush

cmdDump :: P.Stream s m Token => P.ParsecT s u m Command
cmdDump = token "dump" >> return CommandDump

cmdSPDFlush :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDFlush = token "spdflush" >> return CommandSPDFlush

cmdSPDDump :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDDump = token "spddump" >> return CommandSPDDump

parser = 
  P.many1 (do
              cmd <- P.choice [ cmdFlush
                              , cmdDump 
                              , cmdSPDFlush
                              , cmdSPDDump 
                                --               , cmdAdd 
                                --                , cmdGet
                                --                , cmdDelete 
                                --                , cmdDeleteAll 
                              , cmdSPDAdd 
                                --                , cmdSPDDelete
                              ]
              tokenEOC
              return cmd)

{-

key = undefined
cmdAdd = do
  src <- many $ noneOf " \t\n"
  many1 separator
  dst <- string
  many1 separator
  spi <- string
  many1 separator
  string "-E"
  many1 separator
  enc <- string
  many1 separator
  encKey <- key
  many1 separator
  string "-A"
  many1 separator
  auth <- string
  many1 separator
  authKey <- key
  
  return $ CommandAdd { addSrc = src
                      , addDst = dst
                      , addProto = proto
                      , addSPI = spi
                      , addEncAlg = encAlg
                      , addEncKey = encKey
                      , addAuthAlg = authAlg
                      , addAuthKey = authKey
                      }
cmdGet = do
  src <- string
  dst <- string
  proto <- string
  spi <- string
  return $ CommandGet { getSrc = src
                      , getDst = dst
                      , getProto = proto
                      , getSPI = spi
                      }
  
cmdDelete = do
  return $ CommandDelete { deleteSrc = src
                         , deleteDst = dst
                         , deleteProto = proto
                         , deleteSPI = spi
                         }
  
cmdDeleteAll = do
  return $ CommandDeleteAll { deleteAllSrc = src
                            , deleteAllDst = dst
                            , deleteAllProto = proto
                            }
-}

split :: Char -> String -> [String]
split c s = 
  let
    split' acc "" "" = acc
    split' acc ps "" = acc ++ [ps]
    split' acc ps (f:s') = 
      if f == c then
        split' (acc ++ [ps]) "" s'
      else
        split' acc (ps ++ [f]) s'
  in split' [] "" s

{-
trHostAddress :: String -> Maybe HostAddress
trHostAddress s = 
  let
    p = split '.' s
    n :: [Int]
    n = reverse $ fmap read p  
    a = foldl (\s a -> shift s 8 .|. a) 0 n 
  in
   if length p /= 4 then Nothing
   else Just (fromIntegral a)
-}
tokenIP :: P.Stream s m Token => P.ParsecT s u m HostAddress
tokenIP = do
  v1 <- tokenNumber
  tokenDot
  v2 <- tokenNumber
  tokenDot
  v3 <- tokenNumber
  tokenDot
  v4 <- tokenNumber
  return $ fromIntegral $ v1 .|. v2 `shift` 8 .|. v3 `shift` 16 .|. v4 `shift` 24 

tokenPolicy :: P.Stream s m Token => P.ParsecT s u m Policy
tokenPolicy = do
  str <- tokenString
  let dir = (read str) :: IPSecDir
--  direction <- P.choice $ fmap token ["out", "in", "fwd"]
--  prio
  str <- tokenString
--  pol <- P.choice $ fmap token ["discard", "none", "ipsec"]
  let pol = (read str) :: IPSecPolicy
  proto <- P.choice $ fmap token ["ah", "esp", "ipcomp"] 
  tokenSlash
--  mode <- P.choice $ fmap token ["tunnel", "transport"]
  str <- tokenString
  let mode = (read str) :: IPSecMode
  tokenSlash
  addrs <- P.optionMaybe $ do
    src <- tokenIP
    token "-"
    dst <- tokenIP
    return (SockAddrInet 0 src, SockAddrInet 0 dst)
  tokenSlash
  
  str <- tokenString
--  level <- P.choice $ fmap token ["default", "use", "require", "unique"]
  let level = (read str) :: IPSecLevel
             
  let req = IPSecRequest { ipsecreqProto = 0
                         , ipsecreqMode = mode
                         , ipsecreqLevel = level
                         , ipsecreqReqId = 0
                         , ipsecreqAddrs = addrs
                         }
  return $ Policy { policyType = pol
                  , policyDir = dir
                  , policyId = 0
                  , policyPriority = 0
                  , policyIPSecRequests = [req]
                  }
  
tokenAddressRange :: P.Stream s m Token => P.ParsecT s u m Address
tokenAddressRange = do
  ip <- tokenIP
  P.choice [ do
                return $ Address { addressProto = 0
                                 , addressPrefixLen = 32
                                 , addressAddr = SockAddrInet 0 ip
                                 }
           , do
                tokenSlash
                pref <- tokenNumber
                return undefined
           , do
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return undefined
           , do
                tokenSlash
                pref <- tokenNumber
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return undefined
           ]

cmdSPDAdd :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDAdd = do
  token "spdadd"
  src <- tokenAddressRange
  dst <- tokenAddressRange
  str <- tokenString
  let upper = (read str) :: IPProto
  token "-"
  token "P"
  pol <- tokenPolicy
  return $ CommandSPDAdd { spdAddSrcRange = src
                         , spdAddDstRange = dst
                         , spdAddUpperspec = upper
                         , spdAddLabel = Nothing
                         , spdAddPolicy = pol
                         }

{-
cmdSPDDelete :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDDelete = do
  return $ CommandSPDDelete { spdDeleteSrcRange = srcRange
                            , spdDeleteDstRange = dstRange
                            , spdDeleteUppperspec = upperSpec
                            , spdDeleteDirection = direction
                            }
-}

data Command = CommandFlush
             | CommandDump
             | CommandSPDFlush
             | CommandSPDDump
             | CommandAdd { addSrc :: String
                          , addDst :: String
                          , addProto :: String
                          , addSPI :: String
                          , addEncAlg :: String
                          , addEncKey :: String
                          , addAuthAlg :: String
                          , addAuthKey :: String
                          , addCompAlg :: String
                          }
             | CommandGet { getSrc :: String
                          , getDst :: String
                          , getProto :: String
                          , getSPI :: String
                          }
             | CommandDelete { deleteSrc :: String
                             , deleteDst :: String
                             , deleteProto :: String
                             , deleteSPI :: String
                             }
             | CommandDeleteAll { deleteAllSrc :: String
                                , deleteAllDst :: String
                                , deleteAllProto :: String
                                }
             | CommandSPDAdd { spdAddSrcRange :: Address
                             , spdAddDstRange :: Address
                             , spdAddUpperspec :: IPProto
                             , spdAddLabel :: Maybe String
                             , spdAddPolicy :: Policy
                             }
             | CommandSPDAddTagged { spdAddTaggedTag :: String
                                   , spdAddTaggedPolicy :: String
                                   }
             | CommandSPDDelete { spdDeleteSrcRange :: String
                                , spdDeleteDstRange :: String
                                , spdDeleteUppperspec :: String
                                , spdDeleteDirection :: String
                                }
             deriving (Show)

