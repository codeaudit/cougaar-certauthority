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
package org.cougaar.core.security.crypto;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.cougaar.core.security.certauthority.ConfigPlugin;
import org.cougaar.core.security.certauthority.servlet.CAInfo;

/*
 * This class only add trusted policy and trusted CA certificate,
 * it does not request certificate from the CA, this is used for 
 * multiple root CA so that their subordinate CAs can trust each other.
 */

public class TrustedCAConfigPlugin extends ConfigPlugin {
  Vector calist = new Vector();

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() == 0) {
      System.out.println("No CA assigned!");
    }
    Iterator it = l.iterator();
    while (it.hasNext()) {
      String param = (String)it.next();
      calist.addElement(param);
    }

  }

  protected void execute() {
    if (log.isDebugEnabled()) {
      log.debug("executing ... ");
    }
    for (int i = 0; i < calist.size(); i++) {
      addTrustedPolicy((String)calist.elementAt(i), true);
    }
  }

  /** Need to synchronize because for normal node there could be multiple threads
   */
  protected synchronized void checkOrMakeIdentity(CAInfo info, String requestURL) {
  }

}
