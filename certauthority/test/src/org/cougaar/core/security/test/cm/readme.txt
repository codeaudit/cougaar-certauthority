CM TEST:
Add the CMTestServlet and CMTestPlugin to an agent.

Go to the CMTestServlet using /testCMServlet?node=moveToNode url pattern

The CMTestPlugin will ask the CMService to verify that the agent can be put on the moveToNode.  

The CMTestPlugin will then output the result from the CM using the log4j.info()