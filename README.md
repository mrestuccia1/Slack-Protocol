### Project Description
This is an implementation of the IRC (Internet Relay Chat) protocol in accordance with the RFC. This is the protocol that Slack runs on behind the scenes. 

### How to Run

### User Registration 
Users will be able to connect to the server by running:
* NICK <Your desired nickname>
* USER <Your desisered username> * * :<Your full name>

### User Commands  
Once registered, users can do the following:
* Join or create new channels using the JOIN command (e.g. JOIN #example)
* Privately message users or channels (e.g. Message a _test_ user/channel using PRIVMSG _test_ :Your Message)
* List the users and channels in the server using LIST
* Set moderatoror priviledges, away messages and more, in accordance to [this](https://datatracker.ietf.org/doc/html/rfc2812#section-3.1.5)

### Distributed Sytem  
If a user has operator priviledges, they may register a new server to connect with the current server. This serves the purpose of turning this into a distributed system, making it more robust to one server's failure. Each connected server shares the exact same information, and a new one can be registered as follows:

### Credits
The tests and the some setup was done by my professor, and I worked with a partner on this. To see my code, the bulk of my work was in src/handlers.c and src/server.c.
