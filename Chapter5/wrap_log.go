// Go universal wrap and logger
package main 
import (
    "fmt"
    "os"
    "os/user"
    "os/exec"
    "time"
    "io/ioutil"

)
  
func main() {
  
  //Prep vars
  logFile := "log.txt";
  hostName, _ := os.Hostname();
  user, _ := user.Current();
  programName := os.Args[0];
  
  //Check for backup program?
  backStatus := "backup program is there";
  if !Exists(programName+".bak") { backStatus = "backup program is not there"; }
  
  //Notify area
  notification := fmt.Sprintf("%s: User %s is calling %s on %s and %s \n", time.Now(), user.Username, programName, hostName, backStatus);
  //Send or store notification
  //fmt.Println(notification);
  err := WriteFile(notification, logFile);
 
  //Execute
  results, _ := RunCommand(programName+".bak", os.Args[1:]);
  
  //Send results back to user
  fmt.Println(results);
}

func RunCommand(cmd string, args []string) (string, error) {
  out, err := exec.Command(cmd, args...).CombinedOutput()
  if err != nil {
    return string(out), err
  }
  return string(out), nil
}

func Exists(path string) bool {
  //Run stat on a file
  _, err := os.Stat(path)
  //If it runs fine the file exists
  if err == nil {
    return true
  }
  //If stat fails then the file does not exist
  return false
}

func WriteFile(text, logfile string) (error) {
  //Check if log file exists to create or append
  if Exists(logfile) {
    //Write the lines to the file
    f, err := os.OpenFile(logfile,
	os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
	  return err
    }
    defer f.Close()
    if _, err := f.WriteString(text); err != nil {
	  return err
    }  
  } else {
    //Create file and write first lines
	err := ioutil.WriteFile(logfile, []byte(text), 0700)
	if err != nil {
      return err
    }
  }
  return nil
}
