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
package org.cougaar.core.security.test.cm;

import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.servlet.AbstractServletComponent;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;
/**
 *Servlet to test the Configuration Manager. When invoked, it will publish a Task to the 
 *Blackboard which is subscribed to by the CMTestPlugin.  The URL Param <i>node</i> will
 *be passed to the plugin as the node name to try to move this agent to.  An Example test would 
 *be to pass the name of a Management node to this servlet while this agent is not on a management 
 *node. and vice versa. 
 * @author ttschampel
 *
 */
public class CMTestServlet extends AbstractServletComponent{

	public static final String CM_TEST_VERB="CMTESTVERB";
	public static final String GET_RESULT_URL_PARAM="getresult";
	public static final String SUCCESS_PHRASE = "success phrase";
	public static final String CM_TEST_VERB_RESPONSE="CMTESTVERBRESPONSE";
	public static final String DEST_NODE_PREP="DESTNODEPREP";
	public static final String TYPE_URL_PARAM="testtype";
	public static final String NODE_URL_PARAM="node";
	
	/**
	 * Get Path to the Servlet
	 */
	protected String getPath() {
		return "/testCMServlet";
	}

/**
 * process requeest
 */
	protected void execute(HttpServletRequest request, HttpServletResponse response) {
		String node = request.getParameter(NODE_URL_PARAM);
		String resultParam = request.getParameter(GET_RESULT_URL_PARAM);
		String testTypeParam = request.getParameter(TYPE_URL_PARAM);
		
		if(node==null || node.trim().length()==0){
			if(logging.isErrorEnabled()){
				logging.error("Must pass node name as using node url parameter");
			}
		}else if(resultParam==null){
			PlanningFactory ldm = (PlanningFactory)domainService.getFactory("planning");
			NewTask task = ldm.newTask();
			task.setVerb(Verb.getVerb(CM_TEST_VERB));
			NewPrepositionalPhrase nodePrep = ldm.newPrepositionalPhrase();
			nodePrep.setPreposition(DEST_NODE_PREP);
			nodePrep.setIndirectObject(node);
			task.addPrepositionalPhrase(nodePrep);
			this.blackboardService.openTransaction();
			this.blackboardService.publishAdd(task);
			this.blackboardService.closeTransactionDontReset();
		}else{
			try{
				this.blackboardService.openTransaction();
				Collection coll = this.blackboardService.query(new UnaryPredicate(){
					public boolean execute(Object o){
						if(o instanceof Task){
							Task t= (Task)o;
							return t.getVerb()!=null && t.getVerb().toString().equals(CM_TEST_VERB_RESPONSE);
						}
						return false;
					}
				  }
				
				);
				String result = "FALSE";
				boolean success = false;
				Iterator iterator = coll.iterator();
				while(iterator.hasNext()){
					Task t = (Task)iterator.next();
					success = ((Boolean)t.getPrepositionalPhrase(SUCCESS_PHRASE).getIndirectObject()).booleanValue();
					this.blackboardService.publishRemove(t);
				}
				this.blackboardService.closeTransactionDontReset();
				if(testTypeParam.equals("L") && success){
					result= "TRUE";
				}else if(testTypeParam.equals("M") && success==false){
					result="TRUE";
				}
				PrintWriter out = response.getWriter();
				out.println(result);
				out.close();
			}catch(Exception e){
				if(logging.isErrorEnabled()){
					logging.error("Error checking result of cm test",e);
				}
			}
		}
		
	}

}
