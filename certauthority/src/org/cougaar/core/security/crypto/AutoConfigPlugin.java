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

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.cougaar.core.security.certauthority.ConfigPlugin;
import org.cougaar.core.security.certauthority.servlet.CAInfo;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.util.NodeInfo;

import sun.security.x509.X500Name;

public class AutoConfigPlugin extends ConfigPlugin {
  private Vector calist = new Vector();

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
      //log.debug("Unzip & run CA: " + param);
      calist.addElement(param);
    }

  }

  protected void execute() {
    for (int i = 0; i < calist.size(); i++) {
      addTrustedPolicy((String)calist.elementAt(i), (i == 0));
    }
  }

  /** Need to synchronize because for normal node there could be multiple threads
   *  changing cryptoClientPolicy as well as requesting certificates
   */
  protected synchronized void checkOrMakeIdentity(CAInfo info, String requestURL) {
    // check whether already received the policy
    TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
    boolean newPolicy = true;
    for (int i = 0; i < tc.length; i++) {
      if (tc[i].caDN.equals(info.caPolicy.caDN)) {
        newPolicy = false;
        break;
      }
    }
    if (newPolicy) {
      setCAInfo(info, requestURL);
    }

    TrustedCaPolicy tcp = info.caPolicy;

    // request certificates from the particular CA that has started
    // the certificate may have been created
    if (log.isDebugEnabled()) {
      log.debug("CA " + info.caPolicy.caDN + " started, sending requests.");
    }
    X500Name dname = null;
    try {
      String nodename = NodeInfo.getNodeName();
      dname = new X500Name(CertificateUtility.getX500DN(nodename,
      		CertificateCacheConstants.CERT_TITLE_NODE,
        tcp.getCertificateAttributesPolicy()));
    } catch (IOException iox) {}

    keyRingService.checkOrMakeCert(dname, false, tcp);
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.util.GenericStateModel#stop()
   */
  public synchronized void stop() {
    super.stop();
  }
}
