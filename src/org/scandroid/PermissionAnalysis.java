/**
 *
 * Copyright (c) 2009-2012,
 *
 *  Galois, Inc. (Aaron Tomb <atomb@galois.com>, 
 *                Rogan Creswick <creswick@galois.com>, 
 *                Adam Foltzer <acfoltzer@galois.com>)
 *  Steve Suh    <suhsteve@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The names of the contributors may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */
package org.scandroid;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.kau.permission.PermissionMap;
import org.kau.permission.parse;
import org.scandroid.domain.CodeElement;
import org.scandroid.domain.DomainElement;
import org.scandroid.domain.IFDSTaintDomain;
import org.scandroid.flow.FlowAnalysis;
import org.scandroid.flow.InflowAnalysis;
import org.scandroid.flow.OutflowAnalysis;
import org.scandroid.flow.types.FlowType;
import org.scandroid.spec.AndroidSpecs;
import org.scandroid.spec.ISpecs;
import org.scandroid.util.AndroidAnalysisContext;
import org.scandroid.util.CGAnalysisContext;
import org.scandroid.util.CLISCanDroidOptions;
import org.scandroid.util.EntryPoints;
import org.scandroid.util.IEntryPointSpecifier;
import org.scandroid.util.ISCanDroidOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.IFDS.TabulationResult;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.MonitorUtil.IProgressMonitor;
import com.ibm.wala.shrike.*;

public class PermissionAnalysis {
	private static final Logger logger = LoggerFactory
			.getLogger(PermissionAnalysis.class);


	public static void main(String[] args) throws Exception {
		CLISCanDroidOptions options = new CLISCanDroidOptions(args, true);

		File r = new File("Android 4.1.1.txt");
//		File r = new File("Android 2.3. ");
		//			File r = new File("C:\\paladogapi.txt");
		if (!r.isFile() || !r.exists()) {
			throw new FileNotFoundException("파일을 읽을 수 없습니다.");
		}
		PermissionMap pm = new PermissionMap(r);
		
		logger.info("Loading app.");
		AndroidAnalysisContext analysisContext = new AndroidAnalysisContext(options);

		URI summariesURI = options.getSummariesURI();
		InputStream summaryStream = null;
		if (null != summariesURI) {
			File summariesFile = new File(summariesURI);

			if (!summariesFile.exists()) {
				logger.error("Could not find summaries file: " + summariesFile);
				System.exit(1);
			}

			summaryStream = new FileInputStream(summariesFile);
		}

		final List<Entrypoint> entrypoints = EntryPoints
//				.defaultEntryPoints(analysisContext.getClassHierarchy());
				.appModelAllEntry(analysisContext.getClassHierarchy());	
//				.appModelFakeEntry(analysisContext.getClassHierarchy());
		if (entrypoints == null || entrypoints.size() == 0) {
			throw new IOException("No Entrypoints Detected!");
		}
		System.out.println("========Start MakeCGAnalysis");
		HashSet<IMethod> methods = new HashSet<IMethod>();
		int counter = 0;
		for (final Entrypoint entry : entrypoints) {
			if(methods.contains(entry.getMethod())) continue;
			CGAnalysisContext<IExplodedBasicBlock> cgContext = new CGAnalysisContext<IExplodedBasicBlock>(
					analysisContext, new IEntryPointSpecifier() {
						@Override
						public List<Entrypoint> specify(
								AndroidAnalysisContext analysisContext) {
							return Lists.newArrayList(entry);
						}
					});
			Iterator<CGNode> nodes = cgContext.cg.iterator();
			
			while(nodes.hasNext()) {
				HashSet<String> rset = new HashSet<String>();
				IMethod m = nodes.next().getMethod();
				if (!methods.contains(m)) {
					methods.add(m);
					HashSet<String> s = pm.getPermissions(m); // Permission Matching
					if (s!=null) {
						rset.addAll(s);
						System.out.println("Method :"+m);
						System.out.println("Permissions :"+ rset);
					}
				}				
			}
			counter++;
			
//			System.out.println(">>>>>>"+counter+entry.toString());
		}
		
		System.out.println("<<<<<<Start Method To Permission matching~~~");
		
		
		

		System.out.println("<<<<<<<<<<Callgraph complete!!!!");
		


		System.exit(11);
	}

	/**
	 * @param analysisContext
	 * @param localEntries
	 * @param methodAnalysis
	 * @param monitor
	 * @return the number of permission outflows detected
	 * @throws IOException
	 */

	 
	public static void traverse( File file , PermissionMap pm) {
	      // Print the name of the entry
	      System.out.println( file ) ;

	      // Check if it is a directory
	      if( file.isDirectory() )
	      {
	         // Get a list of all the entries in the directory
	         String entries[] = file.list() ;

	         // Ensure that the list is not null
	         if( entries != null )
	         {
	            // Loop over all the entries
	            for( String entry : entries )
	            {
	               // Recursive call to traverse
	               traverse( new File(file,entry), pm ) ;
	            }
	         }
	         
	      } 
	      else if (file.getName().endsWith("java")) {
	    	  System.out.println(file);
	      }
	   }

	public static void permissionAnalyze(List<Entrypoint> entrypoints) throws FileNotFoundException {
		try {
			System.out.println("Permission Analysis");
//			logger.info("Supergraph size = "
//					+ analysisContext.graph.getNumberOfNodes()); //CG Node의 갯수 출력 com.ibm.wala.util.graph.nodeManager

			File r = new File("C:\\Android 4.1.1.txt");
//			File r = new File("Android 2.3. ");
			//			File r = new File("C:\\paladogapi.txt");
			if (!r.isFile() || !r.exists()) {
				throw new FileNotFoundException("파일을 읽을 수 없습니다.");
			}
			PermissionMap pm = new PermissionMap(r);
			
//			Iterator<Entrypoint> e = analysisContext.getEntrypoints().iterator();
			Iterator<Entrypoint> e = entrypoints.iterator();
			
			HashSet<String> hs = new HashSet<String>();
			while (e.hasNext()) {
				Entrypoint ep = e.next();
				HashSet<String> pms = pm.getPermissions(ep.getMethod());
				if (pms!=null) {
					hs.addAll(pms);
					System.out.println(ep.getMethod());
					System.out.println(pms);
				}
			}
			
			System.out.println(hs);
			System.exit(0);
			
		} catch (com.ibm.wala.util.debug.UnimplementedError e) {
			logger.error("exception during analysis", e);
		}
	}
 
	@SuppressWarnings("unused")
	public static void permissionAnalyze (

			CGAnalysisContext<IExplodedBasicBlock> analysisContext,
			InputStream summariesStream, IProgressMonitor monitor)
					throws IOException { 
		
		try {
			System.out.println("Permission Analysis");
			logger.info("Supergraph size = "
					+ analysisContext.graph.getNumberOfNodes()); //CG Node의 갯수 출력 com.ibm.wala.util.graph.nodeManager

			File r = new File("C:\\Android 4.1.1.txt");
//			File r = new File("Android 2.3. ");
			//			File r = new File("C:\\paladogapi.txt");
			if (!r.isFile() || !r.exists()) {
				throw new FileNotFoundException("파일을 읽을 수 없습니다.");
			}
			PermissionMap pm = new PermissionMap(r);
			
			Iterator<Entrypoint> e = analysisContext.getEntrypoints().iterator();
			
			HashSet<String> hs = new HashSet<String>();
			while (e.hasNext()) {
				Entrypoint ep = e.next();
				HashSet<String> pms = pm.getPermissions(ep.getMethod());
				if (pms!=null) {
					hs.addAll(pms);
					System.out.println(ep.getMethod());
					System.out.println(pms);
				}
			}
			
			System.out.println(hs);
			System.exit(0);
			
		} catch (com.ibm.wala.util.debug.UnimplementedError e) {
			logger.error("exception during analysis", e);
		}
	}




	public static void reachable(HashSet<CGNode> set, CGNode node, CallGraph cg) {
		set.add(node);
		//		PrintWriter out = new PrintWriter(new FileWriter("C:\\output.txt"));
		Iterator<CGNode> succ = cg.getSuccNodes(node);//추가
		while(succ.hasNext()){
			CGNode s = succ.next();

			System.out.println(node.getMethod() + "-->" + s.getMethod());
			//				out.write(node.getMethod() + "-->" + s.getMethod());
			//				out.println(" "+node.getMethod() + "-->" + s.getMethod() + "\r\n");
			if (set.contains(s)) {
				continue;
			}
			//			reachable(set, s, cg);
		}
	}
	public static int analyze(
			CGAnalysisContext<IExplodedBasicBlock> analysisContext,
			InputStream summariesStream, IProgressMonitor monitor)
					throws IOException {
		try {

			logger.info("Supergraph size = "
					+ analysisContext.graph.getNumberOfNodes()); //CG Node의 갯수 출력 com.ibm.wala.util.graph.nodeManager
			//System.out.println(analysisContext.graph);


			Map<InstanceKey, String> prefixes;
			if (analysisContext.getOptions().stringPrefixAnalysis()) {
				logger.info("Running prefix analysis.");
				prefixes = UriPrefixAnalysis.runAnalysisHelper(
						analysisContext.cg, analysisContext.pa);
				logger.info("Number of prefixes = " + prefixes.values().size());
			} else {
				prefixes = new HashMap<InstanceKey, String>();
			}

			ISpecs specs = new AndroidSpecs();

			logger.info("Running inflow analysis.");
			Map<BasicBlockInContext<IExplodedBasicBlock>, Map<FlowType<IExplodedBasicBlock>, Set<CodeElement>>> initialTaints = InflowAnalysis
					.analyze(analysisContext, prefixes, specs);

			logger.info("  Initial taint size = " + initialTaints.size());

			logger.info("Running flow analysis.");
			IFDSTaintDomain<IExplodedBasicBlock> domain = new IFDSTaintDomain<IExplodedBasicBlock>();
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, DomainElement> flowResult = FlowAnalysis
					.analyze(analysisContext, initialTaints, domain, monitor);

			logger.info("Running outflow analysis.");
			Map<FlowType<IExplodedBasicBlock>, Set<FlowType<IExplodedBasicBlock>>> permissionOutflow = new OutflowAnalysis(
					analysisContext, specs).analyze(flowResult, domain);
			logger.info("  Permission outflow size = "
					+ permissionOutflow.size());

			// logger.info("Running Checker.");
			// Checker.check(permissionOutflow, perms, prefixes);

			logger.info("");
			logger.info("================================================================");
			logger.info("");

			for (Map.Entry<BasicBlockInContext<IExplodedBasicBlock>, Map<FlowType<IExplodedBasicBlock>, Set<CodeElement>>> e : initialTaints
					.entrySet()) {
				logger.info(e.getKey().toString());
				for (Map.Entry<FlowType<IExplodedBasicBlock>, Set<CodeElement>> e2 : e
						.getValue().entrySet()) {
					logger.info(e2.getKey() + " <- " + e2.getValue());
				}
			}
			for (Map.Entry<FlowType<IExplodedBasicBlock>, Set<FlowType<IExplodedBasicBlock>>> e : permissionOutflow
					.entrySet()) {
				logger.info(e.getKey().toString());
				for (FlowType t : e.getValue()) {
					logger.info("    --> " + t);
				}
			}
			return permissionOutflow.size();
		} catch (com.ibm.wala.util.debug.UnimplementedError e) {
			logger.error("exception during analysis", e);
		}
		return 0;
	}
}
