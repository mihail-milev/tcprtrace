package main

import (
  "sync"
  "container/list"
  "fmt"
  "time"
  "strings"
  "os"
)

const (
  COLUMN_WIDTH = "41,41,20,20,8"
  COLUMNS = "FROM,TO,START,DURATION,STATUS"
  SCREEN_REFRESH_NANOSECONDS = 1000000000
  FINISHED_DELETE_THRESHOLD_ON_TOP_NANOSECONDS = 3000000000
)

func GenerateStringFormat() (string, string) {
  colwidths := strings.Split(COLUMN_WIDTH, ",")
  cols := strings.Split(COLUMNS, ",")
  format := ""
  header := ""
  for i, v := range cols {
    format += "%" + colwidths[i] + "s"
    header += fmt.Sprintf("%" + colwidths[i] + "s", v)
  }
  format += "\n"
  header += "\n"
  return format, header
}

func StartVisualizer(chainmap *map[string]*list.List, chainmapmutex *sync.Mutex, timeout float64, outfilepath string) {
  outfile, err := os.OpenFile(outfilepath, os.O_APPEND|os.O_WRONLY, 0644)
  if err != nil {
    return
  }
  defer outfile.Close()
  filewritethresholdduration := int64(timeout * 1000000000)
  deletethresholdduration := FINISHED_DELETE_THRESHOLD_ON_TOP_NANOSECONDS + filewritethresholdduration
  format, header := GenerateStringFormat()
  for {
    fmt.Print("\033[H\033[2J")
    fmt.Printf(header)
    for _, v := range *chainmap {
      var subitm *list.List = v
      if subitm.Len() > 0 {
        iters := subitm.Front()
        itere := subitm.Back()
        firstitem, ok1 := iters.Value.(ParsedPacket)
        lastitem, ok2 := itere.Value.(ParsedPacket)
        if ok1 && ok2 {
          stat := "A"
          dur := time.Now().Sub(firstitem.PacketTime).String()
          if strings.ContainsAny(lastitem.PacketType, "FR") {
            stat = "F"
            dur = lastitem.PacketTime.Sub(firstitem.PacketTime).String()
          }
          deletefunc := func() {
            chainmapmutex.Lock()
            delete(*chainmap, firstitem.HashId)
            chainmapmutex.Unlock()
          }
          fmt.Printf(format, firstitem.SrcAddress, firstitem.DstAddress, firstitem.PacketTime.Format("15:04:05.000000"), dur, stat)
          if stat == "F" && time.Now().Sub(lastitem.PacketTime) > time.Duration(deletethresholdduration) {
            deletefunc()
          } else if stat == "A" && time.Now().Sub(lastitem.PacketTime) > time.Duration(filewritethresholdduration) {
            for ; iters != nil; iters = iters.Next() {
              curitem, isok := iters.Value.(ParsedPacket)
              if isok {
                outfile.Write([]byte(curitem.PacketString + "\n"))
              }
            }
            deletefunc()
          }
        }
      }
    }
    time.Sleep(time.Duration(SCREEN_REFRESH_NANOSECONDS))
  }
}
