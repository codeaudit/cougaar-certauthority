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


/**
 * Conifiguration Manager Message
 * 	Request and Response are both in the Message so 
 *  the calling component can easily match request
 *  to response.
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class CMMessage implements Serializable {
  private CMRequest request;
  private CMResponse response;

  /**
   * Get Request
   *
   * @return
   */
  public CMRequest getRequest() {
    return request;
  }


  /**
   * Set Request
   *
   * @param request
   */
  public void setRequest(CMRequest request) {
    this.request = request;
  }


  /**
   * Set Response
   *
   * @return
   */
  public CMResponse getResponse() {
    return response;
  }


  /**
   * Get Response
   *
   * @param response
   */
  void setResponse(CMResponse response) {
    this.response = response;
  }

  /**
   * CMRequest interface
   *
   * @author ttschampel
   */
  public interface CMRequest {
  }


  /**
   * CM Response Interface
   *
   * @author ttschampel
   */
  public interface CMResponse {
  }
}
