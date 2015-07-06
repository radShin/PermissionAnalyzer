package org.kau.permission;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.types.TypeName;
import com.ibm.wala.types.TypeReference;

class Method {
	public String cname;
	public String mname;
	public String rname;
	public ArrayList<String> args;
	Method(String cname, String mname,String rname, ArrayList<String> args) {
		this.cname = cname;
		this.mname = mname;
		this.rname = rname;
		this.args = new ArrayList<String>();
		this.args = args;
	}
	public int hashCode() {
		return (cname+"@"+mname+"@"+rname).hashCode();
	}
	public boolean equals(Method m) {
		boolean result = (this.cname == m.cname &&
		this.rname == m.rname &&
		this.mname == m.mname && this.args.toString() == m.args.toString());
//		if (this.mname.equals("vibrate") && m.mname.equals("vibrate")) {
//			System.out.println(m);
//			System.out.println(this);
//		}
		
		return result;
//		if (result)
//			return this.args.equals(m.args);
//		else 
//			return false;
	}
	public String toString() {
//		return cname+"\n"+rname+"\n"+mname+"\n"+args;
		return cname+":"+rname+":"+mname+":"+args; //+args;
	}
}
public class PermissionMap {
	HashMap<String, HashSet<String>> permToMethod = new HashMap<String, HashSet<String>>() ;
	static HashMap<String, HashSet<String>> methodToPerm = new HashMap<String, HashSet<String>>() ;
	


 

	public PermissionMap(File file) {
		BufferedReader in = null;
		try {
			if (!file.isFile() || !file.exists()) {
				throw new FileNotFoundException("파일을 읽을 수 없습니다.");

			}
			in = new BufferedReader(new FileReader(file));
		}
		catch (IOException e) {
			return;
		}

		String str = null, per = null, cla = null, met = null, ret = null;
		ArrayList<String> args;
		int num = 0;

		try {
			while ((str = in.readLine()) != null) {
				StringTokenizer st = new StringTokenizer(str,"<>:(), ");

				String start = st.nextToken().trim();
				if (start.equals("Permission")) {
					per = st.nextToken();
				}
				else if(str.substring(0,1).equals("<")){
					cla = start.trim();
					ret = st.nextToken().trim();  // return type
					met = st.nextToken().trim();
					args = new ArrayList<String>();
					String arg = "";
					while(st.hasMoreTokens()) {
						arg = st.nextToken();
						args.add(arg);
					}
					try {
						Integer.parseInt(arg);
						args.remove(arg);
					}
					catch(Exception e) {}
					this.add(per, new Method(cla, met, ret, args)); 
					num--;
				}
				else {
					try {
						num = Integer.parseInt(start);
					}
					catch (NumberFormatException e) {
						System.out.println("Exceptional String");
					}
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public HashSet<String> getPermissions(String method) {
		return methodToPerm.get(method);
	}
	
	public static String typeToString(TypeReference tr) {
		String result;
		if (tr.isClassType())  
			return tr.getName().toString().replaceAll("/", ".").substring(1);

		if (tr.isPrimitiveType()) {
			if (tr.equals(TypeReference.Boolean)) return "boolean";
			if (tr.equals(TypeReference.Byte)) return "byte";
			if (tr. equals(TypeReference.Void)) return "void";
			if (tr.equals(TypeReference.Char)) return "char";
			if (tr.equals(TypeReference.Double)) return "double";
			if (tr.equals(TypeReference.Float)) return "float";
			if (tr.equals(TypeReference.Int)) return "int";
			if (tr.equals(TypeReference.Long)) return "long";
			if (tr.equals(TypeReference.Short)) return "short";
		}
		if (tr.isArrayType()) {
			return typeToString(tr.getArrayElementType())+"[]"; //??
		}
		return "";
	}
	
	public HashSet<String> getPermissions(IMethod method) {
		String mname = method.getName().toString();
		if (mname.equals("<clinit>")) mname = "<init>";
		String cname = method.getDeclaringClass().getName().toString().replaceAll("/", ".").substring(1);
		String rname = typeToString(method.getReturnType());
		
		int pnum = method.getNumberOfParameters();
		ArrayList<String> args = new ArrayList<String>();

//		System.out.println("mname: " +mname);
//		System.out.println("cname: " +cname);
//		System.out.println("rname: " +rname);
		for (int i=0; i<pnum; i++) {
			if (i==0 && !method.isStatic()) continue;
			args.add(typeToString(method.getParameterType(i)));
//			System.out.println("args: " +typeToString(method.getParameterType(i)));
		}
		Method m =new Method(cname, mname, rname, args);
		HashSet<String> ps = getPermissions(m.toString());
		//여기서 new 로 생성시 생성인자값이 같더라도,  다르다
//		if (ps!=null) {
//			System.out.println("><><><"+method);
//			System.out.println("><><><"+ps);
//		}
		return ps;
	}

	public HashSet<String> getMethods(String perm) {
		return permToMethod.get(perm.indexOf(1));
	}

	public void add(String perm, Method method) {
		HashSet<String> perms = methodToPerm.get(method.toString());
		if (perms == null) {
			perms = new HashSet<String>();
		}
		perms.add(perm);
		methodToPerm.put(method.toString(),  perms);
		
		HashSet<String> methods = permToMethod.get(perm);
		if (methods == null) 
			methods = new HashSet<String>();
		methods.add(method.toString());
		permToMethod.put(perm,  methods);
	}

	public void printPermToMethod() {
		Set<String> perms = permToMethod.keySet();
		Iterator<String> itr =perms.iterator();
		String s = null;
		while (itr.hasNext()) {
			s = itr.next();
			System.out.println("Permission : "+s);
			System.out.println("target class/method : "+getMethods(s));
			System.out.println();
		}
	}	

	public void printMethodToPerm() {
		Set<String> methodTP = methodToPerm.keySet();
		Iterator<String> itr = methodTP.iterator();
		String s = null;
		while(itr.hasNext()){
			s = itr.next();
			System.out.println(">>>>>>>"+s);
			System.out.println("--->"+getPermissions(s));
		}
	}
	
	public String toString() {
		Set<String> perms = permToMethod.keySet();
		Iterator<String> itr =perms.iterator();
		String s = "";
		while (itr.hasNext()) {
			String key = itr.next();
			HashSet<String> value = getMethods(key);
			s = s+"\n"+key+"---->"+value;			
		}
		return s;
	}
}
