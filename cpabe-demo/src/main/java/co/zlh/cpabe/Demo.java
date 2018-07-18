package co.zlh.cpabe;

import co.zlh.bswabe.*;


public class Demo {
	final static boolean DEBUG = true;

	static String dir = "demo/cpabe";

    static String pubfile = dir + "/pub_key";
	static String mskfile = dir + "/master_key";
	static String prvfile = dir + "/prv_key";

	static String inputfile = dir + "/input.pdf";
	static String encfile = dir + "/input.pdf.cpabe";
	static String decfile = dir + "/input.pdf.new";

	//static String[] attr = {"a","b","c","d","e","f"};
	static String[] attr = {"0","1","2","3","4"};
	//static String policy= "a b 2of2 d 2of2 e 2of2 f g 2of3" ;
	static String policy= "0 1 2of2 2 2of2 3 2of2 4 2of2" ;


//	static String student_attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
//			+ "sn:student2 cn:student2 uid:student2 userPassword:student2 "
//			+ "ou:idp o:computer mail:student2@sdu.edu.cn title:student";

//	static String student_attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
//			+ "cn:student2 uid:student2 userPassword:student2 "
//			+ "ou:idp o:computer mail:student2@sdu.edu.cn title:student";
//
//	static String student_policy = "sn:student2 cn:student2 uid:student2 2of3 title:student 2of2" ;


	public static void main(String[] args) throws Exception {
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		BswabePrv prv;
		BswabeCph cph;
		BswabeCphKey cphKey;
		BswabeElementBoolean beb;

		long startTime=System.currentTimeMillis();   //获取开始时间
		println("//start to setup");
		Bswabe.setup(pub, msk);
		println("//end to setup");

		println("//start to keygen");
		prv = Bswabe.keygen(pub,msk,attr);
		println("//end to keygen");

		println("//start to enc");
		cphKey = Bswabe.enc(pub,policy);
		println("//end to enc");
		cph = cphKey.cph;
		System.out.println("m = " + cphKey.key);

		println("//start to dec");
		beb = Bswabe.dec(pub,prv,cph);
		System.out.println("m = " + beb.e);
		println("//end to dec");
		long endTime=System.currentTimeMillis(); //获取结束时间
		System.out.println("程序运行时间： "+(endTime-startTime)+"ms");
	}

	/* connect element of array with blank */
	public static String array2Str(String[] arr) {
		int len = arr.length;
		String str = arr[0];

		for (int i = 1; i < len; i++) {
			str += " ";
			str += arr[i];
		}

		return str;
	}

	private static void println(Object o) {
		if (DEBUG)
			System.out.println(o);
	}
}
