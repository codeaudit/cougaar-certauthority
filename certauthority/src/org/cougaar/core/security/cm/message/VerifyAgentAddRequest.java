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
 



package org.cougaar.core.security.cm.message;


import java.io.Serializable;

import org.cougaar.core.security.cm.CMMessage.CMRequest;


/**
 * A Configuration Manager Request for verifying and
 * 	add agent request.
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class VerifyAgentAddRequest implements CMRequest, Serializable {
  private String addToNode;
  private String agent;

  /**
   * Creates a new VerifyAgentAddRequest object.
   *
   * @param node name of the node that the agent is to be added to.
   * @param agentArg name of the agent being added to the node
   */
  public VerifyAgentAddRequest(String node, String agentArg) {
    this.addToNode = node;
    this.agent = agentArg;
  }

  /**
   * Get the name of the node that the agent is to be added to.
   *
   * @return node name
   */
  public String getAddToNode() {
    return addToNode;
  }


  /**
   * Get the name of the agent being added to the node
   * 
   * @return agent name
   */
  public String getAgent() {
    return agent;
  }
}
