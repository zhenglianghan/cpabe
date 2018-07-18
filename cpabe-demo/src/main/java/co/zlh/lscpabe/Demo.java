package co.zlh.lscpabe;
import it.unisa.dia.gas.jpbc.Element;

public class Demo {
//    static String[] allAttrs = {"0","1","2","3"};
//    static String[] myAttrs = new String[] {"0", "1", "2"};
//    static String policy = "0 and 1 and (2 or 3)";

    static String[] allAttrs = {"0","1","2","3","4"};
    static String[] myAttrs = new String[] {"0", "1", "2"};
    static String policy = "(2 and 1) and 0";

    public static void main(String[] args) throws Exception{
        LscpabePub pub = new LscpabePub();
        LscpabeMsk msk = new LscpabeMsk();
        LscpabePrv prv;
        LscpabeCph cph;
        LscpabeCphKey cphKey;
        Element m;

        long startTime=System.currentTimeMillis();   //获取开始时间

        System.out.println("start to setup");
        Lscpabe.setup(pub,msk,allAttrs);
        System.out.println("end to setup");

        System.out.println("start to keygen");
        prv = Lscpabe.keygen(pub,msk,myAttrs);
        System.out.println("end to keygen");

        System.out.println("start to enc");
        cphKey = Lscpabe.enc(pub,policy);
        cph = cphKey.cph;
        System.out.println("end to enc");

        System.out.println("start to dec");
        m = Lscpabe.dec(pub,cph,prv);
        System.out.println("m = " + m);
        System.out.println("end to dec");

        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");

    }
}
