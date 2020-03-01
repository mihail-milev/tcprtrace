package main

import (
  "os/exec"
  "errors"
  //"fmt"
  "strings"
  "io/ioutil"
  "io"
  "container/list"
  "sync"
)

const (
  TCPDUMP_COMMAND = "tcpdump -nl"
)

func CommandOutputReader(stdoutIn io.Reader, newmsgchan chan bool, actfunc func(string)) error {
  buffer := make([]byte, 1024)
  cummulated := ""
  for {
    n, err := stdoutIn.Read(buffer)
    cummulated = cummulated + string(buffer[:n])
    slice := strings.Split(cummulated, "\n")
    sn := len(slice)
    for i := 0; i < sn - 1; i++ {
      actfunc(slice[i])
      newmsgchan <- true
    }
    cummulated = slice[sn-1]
    if err != nil {
      if err == io.EOF {
        break
      } else {
        return err
      }
    }
  }

  return nil
}

func StartTcpDump(newmsgchan chan bool, msglist *list.List, msglistmutex *sync.Mutex, interf, filter string) error {
  cmd := exec.Command("sh", "-c", TCPDUMP_COMMAND + " " + interf + " " + filter)

  stdoutIn, err := cmd.StdoutPipe()
  if err != nil {
		return err
	}
  defer stdoutIn.Close()
	stderrIn, err := cmd.StderrPipe()
  if err != nil {
		return err
	}
  defer stderrIn.Close()

	err = cmd.Start()
	if err != nil {
		return err
	}

  actfunc := func(item string) {
    msglistmutex.Lock()
    msglist.PushBack(item)
    msglistmutex.Unlock()
  }

  err = CommandOutputReader(stdoutIn, newmsgchan, actfunc)
  if err != nil {
    return err
  }

  stderr, err := ioutil.ReadAll(stderrIn)
  if err != nil {
    return err
  }
  strstderr := string(stderr)

  if strstderr != "" {
    return errors.New("tcpdump: " + strstderr)
  }

  return nil
}
