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



/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 1999-2002 The Apache Software Foundation.  All rights 
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:  
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Xerces" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written 
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 1999, International
 * Business Machines, Inc., http://www.apache.org.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

package org.cougaar.core.security.config;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.XMLReaderFactory;

public class ConfigWriter
  extends BaseConfigHandler
  implements LexicalHandler
{
  private static Logger _log;

  //
  // Constants
  //

  // feature ids

    /** Namespaces feature id (http://xml.org/sax/features/namespaces).
     */
  protected static final String NAMESPACES_FEATURE_ID = "http://xml.org/sax/features/namespaces";

  /** Validation feature id (http://xml.org/sax/features/validation).
   */
  protected static final String VALIDATION_FEATURE_ID = "http://xml.org/sax/features/validation";

  /** Schema validation feature id (http://apache.org/xml/features/validation/schema).
   */
  protected static final String SCHEMA_VALIDATION_FEATURE_ID = "http://apache.org/xml/features/validation/schema";

  /** Schema full checking feature id (http://apache.org/xml/features/validation/schema-full-checking).
   */
  protected static final String SCHEMA_FULL_CHECKING_FEATURE_ID = "http://apache.org/xml/features/validation/schema-full-checking";

  // property ids

  /** Lexical handler property id (http://xml.org/sax/properties/lexical-handler).
   */
  protected static final String LEXICAL_HANDLER_PROPERTY_ID = "http://xml.org/sax/properties/lexical-handler";

  // default settings

  /** Default parser name.
   */
  protected static final String DEFAULT_PARSER_NAME = "org.apache.xerces.parsers.SAXParser";

  /** Default namespaces support (true).
   */
  protected static final boolean DEFAULT_NAMESPACES = true;

  /** Default validation support (false).
   */
  protected static final boolean DEFAULT_VALIDATION = false;

  /** Default Schema validation support (false).
   */
  protected static final boolean DEFAULT_SCHEMA_VALIDATION = false;

  /** Default Schema full checking support (false).
   */
  protected static final boolean DEFAULT_SCHEMA_FULL_CHECKING = false;

  /** Default canonical output (false).
   */
  protected static final boolean DEFAULT_CANONICAL = false;

  //
  // Data
  //

  /** Print writer.
   */
  protected PrintWriter fOut;

  /** Canonical output.
   */
  protected boolean fCanonical;

  /** Element depth.
   */
  protected int fElementDepth;

  protected boolean fXmlHeader = true;

  private String tagInsertionPoint;
  private ByteArrayOutputStream newNode;

  static {
    _log = LoggerFactory.getInstance().createLogger("ConfigWriter");
  }
  //
  // Constructors
  //

  /** Default constructor.
   */
  public ConfigWriter(ServiceBroker sb) {
    super(sb);
  } // <init>()

  //
  // Public methods
  //

  public void insertNodeAfterTag(String tag, ByteArrayOutputStream newNode) {
    tagInsertionPoint = tag;
    this.newNode = newNode;
  }

  /** Sets whether output is canonical. */
  public void setCanonical(boolean canonical) {
    fCanonical = canonical;
  } // setCanonical(boolean)

  /** Sets whether XML header is printed. */
  public void setXmlHeader(boolean xmlHeader) {
    fXmlHeader = xmlHeader;
  } // setXmlHeader(boolean)

  /** Gets the output stream
   */
  public PrintWriter getOutput() {
    return fOut;
  }

  /** Sets the output stream for printing.
   */
  public void setOutput(OutputStream stream, String encoding)
    throws UnsupportedEncodingException {

    if (encoding == null) {
      encoding = "US-ASCII";
    }

    java.io.Writer writer = new OutputStreamWriter(stream, encoding);
    fOut = new PrintWriter(writer);

  } // setOutput(OutputStream,String)

  /** Sets the output writer.
   */
  public void setOutput(java.io.Writer writer) {

    fOut = writer instanceof PrintWriter
      ? (PrintWriter)writer : new PrintWriter(writer);

  } // setOutput(java.io.Writer)

  //
  // ContentHandler methods
  //

  /** Start document.
   */
  public void startDocument() throws SAXException {

    fElementDepth = 0;

    if (!fCanonical && fXmlHeader) {
      fOut.println("<?xml version=\"1.0\" encoding=\"US-ASCII\"?>");
      fOut.flush();
    }

  } // startDocument()

  /** Processing instruction.
   */
  public void processingInstruction(String target, String data)
    throws SAXException {

    if (fElementDepth > 0) {
      fOut.print("<?");
      fOut.print(target);
      if (data != null && data.length() > 0) {
	fOut.print(' ');
	fOut.print(data);
      }
      fOut.print("?>");
      fOut.flush();
    }

  } // processingInstruction(String,String)

  /** Start element.
   */
  public void startElement(String uri, String local, String raw,
			   Attributes attrs) throws SAXException {
    fElementDepth++;
    fOut.print('<');
    fOut.print(raw);
    if (attrs != null) {
      attrs = sortAttributes(attrs);
      int len = attrs.getLength();
      for (int i = 0; i < len; i++) {
	fOut.print(' ');
	fOut.print(attrs.getQName(i));
	fOut.print("=\"");
	normalizeAndPrint(parseContents(attrs.getValue(i)));
	fOut.print('"');
      }
    }
    fOut.print('>');

    if (tagInsertionPoint != null) {
      if (local.equals(tagInsertionPoint)) {
	normalizeAndPrint('\n');
	fOut.print(newNode.toString());
      }
    }
    fOut.flush();

  } // startElement(String,String,String,Attributes)

  /** Characters.
   */
  public void characters(char ch[], int start, int length)
    throws SAXException {
    String s = new String(ch, start, length);
    normalizeAndPrint(parseContents(s));

  } // characters(char[],int,int);

  /** Ignorable whitespace.
   */
  public void ignorableWhitespace(char ch[], int start, int length)
    throws SAXException {

    characters(ch, start, length);
    fOut.flush();

  } // ignorableWhitespace(char[],int,int);

  /** End element.
   */
  public void endElement(String uri, String local, String raw)
    throws SAXException {
    fElementDepth--;
    fOut.print("</");
    fOut.print(parseContents(raw));
    fOut.print('>');
    fOut.flush();

  } // endElement(String)

  //
  // ErrorHandler methods
  //

  /** Warning.
   */
  public void warning(SAXParseException ex) throws SAXException {
    printError("Warning", ex);
  } // warning(SAXParseException)

  /** Error.
   */
  public void error(SAXParseException ex) throws SAXException {
    printError("Error", ex);
  } // error(SAXParseException)

  /** Fatal error.
   */
  public void fatalError(SAXParseException ex) throws SAXException {
    printError("Fatal Error", ex);
    ex.printStackTrace();
    throw ex;
  } // fatalError(SAXParseException)

  //
  // LexicalHandler methods
  //

  /** Start DTD.
   */
  public void startDTD(String name, String publicId, String systemId)
    throws SAXException {
  } // startDTD(String,String,String)

  /** End DTD.
   */
  public void endDTD() throws SAXException {
  } // endDTD()

  /** Start entity.
   */
  public void startEntity(String name) throws SAXException {
  } // startEntity(String)

  /** End entity.
   */
  public void endEntity(String name) throws SAXException {
  } // endEntity(String)

  /** Start CDATA section.
   */
  public void startCDATA() throws SAXException {
  } // startCDATA()

  /** End CDATA section.
   */
  public void endCDATA() throws SAXException {
  } // endCDATA()

  /** Comment.
   */
  public void comment(char ch[], int start, int length) throws SAXException {
    if (!fCanonical && fElementDepth > 0) {
      fOut.print("<!--");
      normalizeAndPrint(ch, start, length);
      fOut.print("-->");
      fOut.flush();
    }
  } // comment(char[],int,int)

  //
  // Protected methods
  //

    /** Returns a sorted list of attributes. */
  protected Attributes sortAttributes(Attributes attrs) {

    AttributesImpl attributes = new AttributesImpl();

    int len = (attrs != null) ? attrs.getLength() : 0;
    for (int i = 0; i < len; i++) {
      String name = attrs.getQName(i);
      int count = attributes.getLength();
      int j = 0;
      while (j < count) {
	if (name.compareTo(attributes.getQName(j)) < 0) {
	  break;
	}
	j++;
      }
      attributes.insertAttributeAt(j, name, attrs.getType(i),
				   attrs.getValue(i));
    }

    return attributes;

  } // sortAttributes(AttributeList):AttributeList

 
  /** Normalizes and prints the given string.
   */
  protected void normalizeAndPrint(String s) {

    int len = (s != null) ? s.length() : 0;
    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);
      normalizeAndPrint(c);
    }

  } // normalizeAndPrint(String)

  /** Normalizes and prints the given array of characters. */
  protected void normalizeAndPrint(char[] ch, int offset, int length) {
    for (int i = 0; i < length; i++) {
      normalizeAndPrint(ch[offset + i]);
    }
  } // normalizeAndPrint(char[],int,int)

  /** Normalizes and print the given character.
   */
  protected void normalizeAndPrint(char c) {

    switch (c) {
    case '<': {
      fOut.print("&lt;");
      break;
    }
    case '>': {
      fOut.print("&gt;");
      break;
    }
    case '&': {
      fOut.print("&amp;");
      break;
    }
    case '"': {
      fOut.print("&quot;");
      break;
    }
    case '\r':
    case '\n': {
      if (fCanonical) {
	fOut.print("&#");
	fOut.print(Integer.toString(c));
	fOut.print(';');
	break;
      }
      // else, default print char
    }
    default: {
      fOut.print(c);
    }
    }

  } // normalizeAndPrint(char)

  /** Prints the error message.
   */
  protected void printError(String type, SAXParseException ex) {

    String s = "[" + type + "] ";
    
    String systemId = ex.getSystemId();
    if (systemId != null) {
      int index = systemId.lastIndexOf('/');
      if (index != -1)
	systemId = systemId.substring(index + 1);
      s = s + systemId;
    }
    s = s + ':' + ex.getLineNumber() + ':' + ex.getColumnNumber();
    s = s + ": " + ex.getMessage();
    _log.warn(s);

  } // printError(String,SAXParseException)

  //
  // Main
  //

  /** Main program entry point.
   */
  public static void main(String argv[]) {

    // is there anything to do?
    if (argv.length == 0) {
      printUsage();
      return;
    }

    // variables
    ConfigWriter writer = null;
    XMLReader parser = null;
    boolean namespaces = DEFAULT_NAMESPACES;
    boolean validation = DEFAULT_VALIDATION;
    boolean schemaValidation = DEFAULT_SCHEMA_VALIDATION;
    boolean schemaFullChecking = DEFAULT_SCHEMA_FULL_CHECKING;
    boolean canonical = DEFAULT_CANONICAL;

    // process arguments
    for (int i = 0; i < argv.length; i++) {
      String arg = argv[i];
      if (arg.startsWith("-")) {
	String option = arg.substring(1);
	if (option.equals("p")) {
	  // get parser name
	  if (++i == argv.length) {
	    _log.warn("error: Missing argument to -p option.");
	  }
	  String parserName = argv[i];

	  // create parser
	  try {
	    parser = XMLReaderFactory.createXMLReader(parserName);
	  }
	  catch (Exception e) {
	    parser = null;
	    _log.warn("error: Unable to instantiate parser ("+parserName+")");
	  }
	  continue;
	}
	if (option.equalsIgnoreCase("n")) {
	  namespaces = option.equals("n");
	  continue;
	}
	if (option.equalsIgnoreCase("v")) {
	  validation = option.equals("v");
	  continue;
	}
	if (option.equalsIgnoreCase("s")) {
	  schemaValidation = option.equals("s");
	  continue;
	}
	if (option.equalsIgnoreCase("f")) {
	  schemaFullChecking = option.equals("f");
	  continue;
	}
	if (option.equalsIgnoreCase("c")) {
	  canonical = option.equals("c");
	  continue;
	}
	if (option.equals("h")) {
	  printUsage();
	  continue;
	}
      }

      // use default parser?
      if (parser == null) {

	// create parser
	try {
	  parser = XMLReaderFactory.createXMLReader(DEFAULT_PARSER_NAME);
	}
	catch (Exception e) {
	  _log.warn("error: Unable to instantiate parser ("+DEFAULT_PARSER_NAME+")");
	  continue;
	}
      }

      // set parser features
      try {
	parser.setFeature(NAMESPACES_FEATURE_ID, namespaces);
      }
      catch (SAXException e) {
	_log.warn("warning: Parser does not support feature ("+NAMESPACES_FEATURE_ID+")");
      }
      try {
	parser.setFeature(VALIDATION_FEATURE_ID, validation);
      }
      catch (SAXException e) {
	_log.warn("warning: Parser does not support feature ("+VALIDATION_FEATURE_ID+")");
      }
      try {
	parser.setFeature(SCHEMA_VALIDATION_FEATURE_ID, schemaValidation);
      }
      catch (SAXNotRecognizedException e) {
         if (_log.isDebugEnabled()) {
           _log.debug("Exception can be ignored");
         }
      }
      catch (SAXNotSupportedException e) {
	_log.warn("warning: Parser does not support feature ("+SCHEMA_VALIDATION_FEATURE_ID+")");
      }
      try {
	parser.setFeature(SCHEMA_FULL_CHECKING_FEATURE_ID, schemaFullChecking);
      }
      catch (SAXNotRecognizedException e) {
        if (_log.isDebugEnabled()) {
          _log.debug("Exception can be ignored");
        }
      }
      catch (SAXNotSupportedException e) {
	_log.warn("warning: Parser does not support feature ("+SCHEMA_FULL_CHECKING_FEATURE_ID+")");
      }

      // setup writer
      if (writer == null) {
	writer = new ConfigWriter(null);
	try {
	  writer.setOutput(System.out, "US-ASCII");
	}
	catch (UnsupportedEncodingException e) {
	  _log.warn("error: Unable to set output.");
	  return;
	}
      }

      // set parser
      parser.setContentHandler(writer);
      parser.setErrorHandler(writer);
      try {
	parser.setProperty(LEXICAL_HANDLER_PROPERTY_ID, writer);
      }
      catch (SAXException e) {
        if (_log.isDebugEnabled()) {
          _log.debug("Exception can be ignored");
        }
      }

      // parse file
      writer.setCanonical(canonical);
      try {
	parser.parse(arg);
      }
      catch (SAXParseException e) {
        if (_log.isDebugEnabled()) {
          _log.debug("Exception can be ignored");
        }
      }
      catch (Exception e) {
        _log.warn("error: Parse error occurred - "+e.getMessage());
        if (e instanceof SAXException) {
          e = ((SAXException)e).getException();
        }
        if (_log.isWarnEnabled()) {
          _log.warn("Unable to parse XML file", e);
        }
      }
    }

  } // main(String[])

  //
  // Private static methods
  //

  /** Prints the usage.
   */
  private static void printUsage() {

    _log.warn("usage: java sax.Writer (options) uri ...");

    _log.warn("options:");
    _log.warn("  -p name  Select parser by name.");
    _log.warn("  -n | -N  Turn on/off namespace processing.");
    _log.warn("  -v | -V  Turn on/off validation.");
    _log.warn("  -s | -S  Turn on/off Schema validation support.");
    _log.warn("           NOTE: Not supported by all parsers.");
    _log.warn("  -f  | -F Turn on/off Schema full checking.");
    _log.warn("           NOTE: Requires use of -s and not supported by all parsers.");
    _log.warn("  -c | -C  Turn on/off Canonical XML output.");
    _log.warn("           NOTE: This is not W3C canonical output.");
    _log.warn("  -h       This help screen.");

    _log.warn("defaults:");
    _log.warn("  Parser:     "+DEFAULT_PARSER_NAME);
    _log.warn("  Namespaces: ");
    _log.warn(DEFAULT_NAMESPACES ? "on" : "off");
    _log.warn("  Validation: ");
    _log.warn(DEFAULT_VALIDATION ? "on" : "off");
    _log.warn("  Schema:     ");
    _log.warn(DEFAULT_SCHEMA_VALIDATION ? "on" : "off");
    _log.warn("  Schema full checking:     ");
    _log.warn(DEFAULT_SCHEMA_FULL_CHECKING ? "on" : "off");
    _log.warn("  Canonical:  ");
    _log.warn(DEFAULT_CANONICAL ? "on" : "off");

  } // printUsage()
  
} // class Writer
