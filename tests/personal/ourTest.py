import socket
import threading                                                                                                        

# boolean for continuing to listen for user input
keepRunning = True


class messageSender:
  def __init__(self, client_socket) -> None:
    self.client_socket = client_socket

  def sendMessage(self, input):
    if input == 'n':
      self.sendNick()

    elif input == 'u':
      self.sendUser()

    elif input == 'q':
      self.sendQuit()

    else:
      newString = input + '\r\n'
      self.client_socket.sendall(newString.encode())

  def sendNick(self):
    message1 = "NICK matteo\r\n"
    self.client_socket.sendall(message1.encode())

  def sendUser(self):
    message2 = "USER matteo * * :Matteo Restuccia\r\n"
    self.client_socket.sendall(message2.encode())
    
  def sendQuit(self):
    message3 = "QUIT :Going to sleep\r\n"
    self.client_socket.sendall(message3.encode())

def connect_to_socket(ip, port):
  try:
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sender = messageSender(client_socket)

    def handleUserInput():
       
      global keepRunning
      while keepRunning:
        user_input = input("'e' to exit. Input n, u, or q to send a quick message.:")

        if (user_input == 'e'):
           keepRunning = False
           return
        
        sender.sendMessage(user_input)

    
    # Connect to the server
    client_socket.connect((ip, port))
      
    print("Connected to", ip, "on port", port)

    # Create a thread
    thread = threading.Thread(target=handleUserInput)

    # Start the thread
    thread.start()
    
    # Listen for responses
    def listenForResp():
      global keepRunning
      while keepRunning:
          response = client_socket.recv(1024).decode()
          if not response:
              break
          print("\nReceived from server:", response.strip())

    listenThread = threading.Thread(target=listenForResp)
    listenThread.start()
    
          
    # join thread
    keepRunning = False
    thread.join()
    listenThread.join()


    # Remember to close the socket when done
    client_socket.close()
        
  except Exception as e:
    print("Connection failed:", e)

hostname = socket.gethostname()
destination_ip = socket.gethostbyname(hostname) #'10.150.58.137'
destination_port = 6667
 
connect_to_socket(destination_ip, destination_port)