import sys  
import time
import logging
import hashlib
import subprocess
# Comment 1: Important Watchdog imports
from watchdog  .observers import Observer 
from watchdog.events import LoggingEventHandler
# Comment 2: Log file output configuration
logging.basicConfig(filename="file_integrity.txt",
                    filemode='a',
	                  level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
hasher = hashlib.sha1()

def main():
  path = input("What is the path of the directory you wish to monitor: ")
  # Comment 3: Starting event handler and observer on target dir
  event_handler = LoggingEventHandler()
  event_handler.on_created = on_created
  observer = Observer()
  observer.schedule(event_handler, path, recursive=True)
  observer.start()
  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    observer.stop()
  observer.join()

def on_created(event):
  # Comment 4: Action to take when new file is written
  subprocess.Popen(['chattr', '+i', event.src_path], bufsize=1)
  with open(event.src_path, 'rb') as afile:
    buf = afile.read()
    hasher.update(buf)
  logging.info(f"Artifact: %s \nFile SHA1: %s\n", event.src_path, hasher.hexdigest())
  print("New file added: {}\n File SHA1: {}\n".format(event.src_path, hasher.hexdigest()))

if __name__ == "__main__":
  main() 
