/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 



package org.cougaar.core.security.cm;


import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;


/**
 * Society Configuration Value Object
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class SocietyConfiguration implements Serializable, UniqueObject {
  private HashMap agentConfigurations;
  private HashMap nodeConfigurations;
  private UID uid;

	/**
	 * @return
	 */
	public HashMap getNodeConfigurations() {
		return nodeConfigurations;
	}

	/**
	 * @param nodeConfigurations
	 */
	public void setNodeConfigurations(HashMap nodeConfigurations) {
		this.nodeConfigurations = nodeConfigurations;
	}

	/**
	 * @return
	 */
	public HashMap getAgentConfigurations() {
		return agentConfigurations;
	}

  /**
   * Creates a new SocietyConfiguration object.
   *
   * @param list List of agent to node mappings.
   */
  public SocietyConfiguration(HashMap agentList, HashMap nodeList) {
    this.agentConfigurations = agentList;
    this.nodeConfigurations = nodeList;
    
  }

  /**
   *Gets UID
   */
  public UID getUID() {
    return uid;
  }


  /**
   *Sets UID
   */
  public void setUID(UID arg0) {
    uid = arg0;
  }
  
  public String toString(){
  	String result="";
	result = result + "\nNode configs:\n";
  	if(nodeConfigurations!=null)
  	{
  		
  		Set entries = nodeConfigurations.keySet();
  		Iterator iter = entries.iterator();
  		while(iter.hasNext()){
  			String key = (String)iter.next();
  			NodeConfiguration nc = (NodeConfiguration)nodeConfigurations.get(key);
  			result = result + nc.getNodeName() +":"+nc.getNodeType()+"\n";
  		}
  	}
	result= result + "\nAgent configs:\n";
  	if(agentConfigurations!=null){
  		Set entries = agentConfigurations.keySet();
  		Iterator iter = entries.iterator();
  		while(iter.hasNext()){
  			String key = (String)iter.next();
  			AgentConfiguration ac = (AgentConfiguration)agentConfigurations.get(key);
  			result = result + ac.getAgentname()+":"+ac.getAgentType()+"\n";
  		}
  	}
  	return result;
  }
}
