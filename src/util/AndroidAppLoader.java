/*
 *
 * Copyright (c) 2009-2012,
 *
 *  Adam Fuchs          <afuchs@cs.umd.edu>
 *  Avik Chaudhuri      <avik@cs.umd.edu>
 *  Steve Suh           <suhsteve@gmail.com>
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

package util;

import static util.MyLogger.log;
import static util.MyLogger.LogLevel.DEBUG;
import static util.MyLogger.LogLevel.INFO;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map.Entry;
import java.util.jar.JarFile;

import prefixTransfer.UriPrefixContextSelector;

import com.ibm.wala.analysis.reflection.ReflectionContextInterpreter;
import com.ibm.wala.classLoader.DexIContextInterpreter;
import com.ibm.wala.classLoader.DexIRFactory;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.IFDS.ICFGSupergraph;
import com.ibm.wala.dataflow.IFDS.ISupergraph;
import com.ibm.wala.dex.util.config.DexAnalysisScopeReader;
import com.ibm.wala.ipa.callgraph.AnalysisCache;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisOptions.ReflectionOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.impl.PartialCallGraph;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.cfa.DefaultSSAInterpreter;
import com.ibm.wala.ipa.callgraph.propagation.cfa.DelegatingSSAContextInterpreter;
import com.ibm.wala.ipa.callgraph.propagation.cfa.DexSSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.callgraph.propagation.SSAContextInterpreter;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.summaries.MethodSummary;
import com.ibm.wala.ipa.summaries.XMLMethodSummaryReader;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.IRFactory;
import com.ibm.wala.ssa.ISSABasicBlock;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.Predicate;
import com.ibm.wala.util.collections.Filter;
import com.ibm.wala.util.config.AnalysisScopeReader;
import com.ibm.wala.util.graph.Graph;
import com.ibm.wala.util.graph.GraphSlicer;
import com.ibm.wala.util.io.FileProvider;
import com.ibm.wala.util.warnings.Warning;
import com.ibm.wala.util.warnings.Warnings;

public class AndroidAppLoader<E extends ISSABasicBlock> {

	public final AnalysisScope scope;
	public final ClassHierarchy cha;
	public final LinkedList<Entrypoint> entries;
	public XMLMethodSummaryReader methodSummaryReader;

	public CallGraph cg;
	public PointerAnalysis pa;
	public ISupergraph<BasicBlockInContext<E>, CGNode> graph;
	public Graph<CGNode> partialGraph;
	public Graph<CGNode> oneLevelGraph;
	public Graph<CGNode> systemToApkGraph;

	public AndroidAppLoader(String classpath) throws IllegalArgumentException,
			ClassHierarchyException, IOException, CancelException {
		this(classpath, new File(CLI.getOption("android-lib")));
	}

	/**
	 * 
	 * @param classpath
	 * @param packagename
	 * @throws IOException
	 * @throws IllegalArgumentException
	 * @throws CancelException
	 * @throws ClassHierarchyException
	 */
	public AndroidAppLoader(String classpath, File androidLib)
			throws IOException, IllegalArgumentException, CancelException,
			ClassHierarchyException {

		// scope =
		// com.ibm.wala.util.config.AnalysisScopeReader.makeJavaBinaryAnalysisScope(classpath,
		// new FileProvider().getFile("conf/Java60RegressionExclusions.txt"));

		scope = DexAnalysisScopeReader.makeAndroidBinaryAnalysisScope(
				classpath, new FileProvider()
						.getFile("conf/Java60RegressionExclusions.txt"));

		scope.setLoaderImpl(ClassLoaderReference.Application,
				"com.ibm.wala.classLoader.WDexClassLoaderImpl");
		scope.addToScope(ClassLoaderReference.Primordial,
				new JarFile(androidLib));

		// AnalysisScope scope =
		// AnalysisScopeReader.makeJavaBinaryAnalysisScope(
		// "/Users/ssuh/Documents/projects/SCanDroid/SimpleAnalysisPluginDexLib/scandroid/SimpleAndroidApp.jar",
		// new
		// FileProvider().getFile("/Users/ssuh/Documents/projects/SCanDroid/SimpleAnalysisPluginDexLib/scandroid/conf/Java60RegressionExclusions.txt"));
		// scope.addToScope(ClassLoaderReference.Primordial, new
		// JarFile("/Users/ssuh/Documents/projects/SCanDroid/SimpleAnalysisPluginDexLib/scandroid/data/android-2.3.7_r1.jar"));

		cha = ClassHierarchy.make(scope);

		// log ClassHierarchy warnings
		for (Iterator<Warning> wi = Warnings.iterator(); wi.hasNext();) {
			Warning w = wi.next();
			log(w);
		}
		Warnings.clear();

		// Try to look for entry points
		EntryPoints ep = new EntryPoints(classpath, cha, this);
		entries = ep.getEntries();
	}

	@SuppressWarnings("deprecation")
	public void buildGraphs(LinkedList<Entrypoint> localEntries)
			throws CancelException {

		AnalysisOptions options = new AnalysisOptions(scope, localEntries);
		for (Entrypoint e : localEntries) {
			MyLogger.log(DEBUG, "Entrypoint: " + e);
		}

		options.setEntrypoints(localEntries);

		if (CLI.hasOption("reflection"))
			options.setReflectionOptions(ReflectionOptions.valueOf(CLI
					.getOption("reflection")));
		else
			options.setReflectionOptions(ReflectionOptions.NONE);

		AnalysisCache cache = new AnalysisCache(
				(IRFactory<IMethod>) new DexIRFactory());
		// AnalysisCache cache = new AnalysisCache();

		// SSAContextInterpreter ci = new
		// DexIContextInterpreter(options.getSSAOptions(), cache);
		// ci = new
		// DelegatingSSAContextInterpreter(ReflectionContextInterpreter.createReflectionContextInterpreter(cha,
		// options, cache), ci);

		SSAPropagationCallGraphBuilder zeroxcgb, cgb;

		// zeroxcgb = Util.makeZeroCFABuilder(options, cache, cha, scope, new
		// UriPrefixContextSelector(options, cha), null);
		zeroxcgb = Util.makeVanillaZeroOneCFABuilder(options, cache, cha,
				scope, new UriPrefixContextSelector(options, cha), null);
		// cgb = new DexSSAPropagationCallGraphBuilder(cha, options, cache,
		// zeroxcgb.getContextSelector(),
		// (SSAContextInterpreter)zeroxcgb.getContextInterpreter(),
		// zeroxcgb.getInstanceKeys());
		cgb = zeroxcgb;

		// CallGraphBuilder construction warnings
		for (Iterator<Warning> wi = Warnings.iterator(); wi.hasNext();) {
			Warning w = wi.next();
			MyLogger.log(w);
		}
		Warnings.clear();

		MyLogger.log(INFO, "*************************");
		MyLogger.log(INFO, "* Building Call Graph   *");
		MyLogger.log(INFO, "*************************");

		cg = cgb.makeCallGraph(options);

		// makeCallGraph warnings
		for (Iterator<Warning> wi = Warnings.iterator(); wi.hasNext();) {
			Warning w = wi.next();
			MyLogger.log(w);
		}
		Warnings.clear();

		pa = cgb.getPointerAnalysis();

		// TODO: prune out a lot more stuff
		partialGraph = GraphSlicer.prune(cg, new Predicate<CGNode>() {
			@Override
			// CallGraph composed of APK nodes
			public boolean test(CGNode node) {
				return fromLoader(node, ClassLoaderReference.Application);
			}
		});

		Collection<CGNode> nodes = new HashSet<CGNode>();

		for (Iterator<CGNode> nIter = partialGraph.iterator(); nIter.hasNext();) {
			nodes.add(nIter.next());
		}

		CallGraph pcg = PartialCallGraph.make(cg, cg.getEntrypointNodes(),
				nodes);

		if (CLI.hasOption("include-library"))
			graph = (ISupergraph) ICFGSupergraph.make(cg, cache);
		else
			graph = (ISupergraph) ICFGSupergraph.make(pcg, cache);

		oneLevelGraph = GraphSlicer.prune(cg, new Predicate<CGNode>() {
			@Override
			public boolean test(CGNode node) {
				// Node in APK
				if (fromLoader(node, ClassLoaderReference.Application)) {
					return true;
				} else {
					Iterator<CGNode> n = cg.getPredNodes(node);
					while (n.hasNext()) {
						// Primordial node has a successor in APK
						if (fromLoader(n.next(),
								ClassLoaderReference.Application))
							return true;
					}
					n = cg.getSuccNodes(node);
					while (n.hasNext()) {
						// Primordial node has a predecessor in APK
						if (fromLoader(n.next(),
								ClassLoaderReference.Application))
							return true;
					}
					// Primordial node with no direct successors or predecessors
					// to APK code
					return false;
				}
			}
		});

		systemToApkGraph = GraphSlicer.prune(cg, new Predicate<CGNode>() {
			@Override
			public boolean test(CGNode node) {

				if (fromLoader(node, ClassLoaderReference.Primordial)) {
					Iterator<CGNode> succs = cg.getSuccNodes(node);
					while (succs.hasNext()) {
						CGNode n = succs.next();

						if (fromLoader(n, ClassLoaderReference.Application)) {
							return true;
						}
					}
					// Primordial method, with no link to APK code:
					return false;
				} else if (fromLoader(node, ClassLoaderReference.Application)) {
					// see if this is an APK method that was
					// invoked by a Primordial method:
					Iterator<CGNode> preds = cg.getPredNodes(node);
					while (preds.hasNext()) {
						CGNode n = preds.next();

						if (fromLoader(n, ClassLoaderReference.Primordial)) {
							return true;
						}
					}
					// APK code, no link to Primordial:
					return false;
				}

				// who knows, not interesting:
				return false;
			}
		});

		methodSummaryReader = new XMLMethodSummaryReader(Util.class
				.getClassLoader().getResourceAsStream(Util.nativeSpec), scope);
		System.out.println("===== Method Summaries =====");
		for (Entry<MethodReference, MethodSummary> mr : methodSummaryReader
				.getSummaries().entrySet()) {
			System.out.println("MethoReference: " + mr.getKey());
			System.out.println("\tMethodSummary: " + mr.getValue());

		}

		if (CLI.hasOption("c"))
			GraphUtil.makeCG(this);
		if (CLI.hasOption("p"))
			GraphUtil.makePCG(this);
		if (CLI.hasOption("o"))
			GraphUtil.makeOneLCG(this);
		if (CLI.hasOption("s"))
			GraphUtil.makeSystemToAPKCG(this);

		if (CLI.hasOption("a")) {
			for (Iterator<CGNode> nodeI = cg.iterator(); nodeI.hasNext();) {
				CGNode node = nodeI.next();

				System.out.println("CGNode: " + node);
				for (Iterator<CGNode> succI = cg.getSuccNodes(node); succI
						.hasNext();) {
					System.out.println("\tSuccCGNode: "
							+ succI.next().getMethod().getSignature());
				}
			}
		}
	}

	static boolean fromLoader(CGNode node, ClassLoaderReference clr) {
		IClass declClass = node.getMethod().getDeclaringClass();

		ClassLoaderReference nodeClRef = declClass.getClassLoader()
				.getReference();

		return nodeClRef.equals(clr);
	}

}
