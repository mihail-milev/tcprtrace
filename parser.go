package main

import (
  "container/list"
  "fmt"
  "regexp"
  "strings"
  "strconv"
  "time"
  "sync"
  "crypto/md5"
  "io"
)

const (
  REGEX_PACKET_PARSE_TERM = `(^\d{1,2}:\d{1,2}:\d{1,2}\.\d{6})\s+IP\d?\s+([0-9a-fA-F:\.]+)\s+[<>]\s+([0-9a-fA-F:\.]+).*?\[(.*?)\]`
)

func CleanIp(ipstr string) (string, int) {
  item := strings.TrimRight(ipstr, ":")
  portpos := strings.LastIndex(item, ".")
  if portpos == -1 {
    return item, 0
  }
  port, err := strconv.Atoi(item[portpos+1:])
  if err != nil {
    return item, 0
  }
  return item[:portpos], port
}

func XorByteArrays(arr1, arr2 []byte) []byte {
  res := make([]byte, len(arr1))
  for i, v := range arr2 {
    res[i] ^= arr1[i] ^ v
  }
  return res
}

func CalculateParsedPacketHash(str1, str2 string) string {
  h1 := md5.New()
  h2 := md5.New()
	io.WriteString(h1, str1)
  io.WriteString(h2, str2)
  valb := XorByteArrays(h1.Sum(nil), h2.Sum(nil))

  return fmt.Sprintf("%x", valb)
}

func StartParser(msglist *list.List, msglistmutex *sync.Mutex, chainmap *map[string]*list.List, chainmapmutex *sync.Mutex, newmsgchan chan bool) {
  re := regexp.MustCompile(REGEX_PACKET_PARSE_TERM)
  for {
    _ = <-newmsgchan
    for msg := msglist.Front(); msg != nil; msg = msg.Next() {

      str, ok := msg.Value.(string)

      msglistmutex.Lock()
      msglist.Remove(msg)
      msglistmutex.Unlock()

      if ok {
        items := re.FindAllStringSubmatch(str, -1)
        if len(items) > 0 && len(items[0]) == 5 {
          ip1, port1 := CleanIp(items[0][2])
          ip2, port2 := CleanIp(items[0][3])
          tm, err := time.Parse("MST 2006-01-02 15:04:05.000000", time.Now().Format("MST 2006-01-02") + " " + items[0][1])
          if err != nil {
            continue
          }
          newitm := ParsedPacket{SrcPort: port1, DstPort: port2, SrcAddress: ip1, DstAddress: ip2, PacketTime: tm, PacketType: items[0][4],
                                  HashId: CalculateParsedPacketHash(fmt.Sprintf("%s.%d", ip1, port1), fmt.Sprintf("%s.%d", ip2, port2)), PacketString: str}

          if newitm.PacketType[:1] == "S" {
            _, ok := (*chainmap)[newitm.HashId]
            if !ok {
              chainmapmutex.Lock()
              (*chainmap)[newitm.HashId] = list.New()
              chainmapmutex.Unlock()
            }
          }

          chainmapmutex.Lock()
          _, ok := (*chainmap)[newitm.HashId]
          if ok {
            ((*list.List)((*chainmap)[newitm.HashId])).PushBack(newitm)
          }
          chainmapmutex.Unlock()

        }
      }
    }
  }
}
