package co.zlh.fscpabe;
import it.unisa.dia.gas.jpbc.Element;

public class Demo {
    static String[] allAttrs = {"0","1","2","3","4"};
    static String[] myAttrs = new String[] {"2","3"};
    static String policy = "((3 and 2) and 1) and 0";

    public static void main(String[] args) throws Exception{
        FscpabePub pub = new FscpabePub();
        FscpabeMsk msk = new FscpabeMsk();
        FscpabePrv prv;
        FscpabeCph cph;
        FscpabeCphKey cphKey;
        Element[] ms;

        System.out.println("start to setup");
        Fscpabe.setup(pub,msk,allAttrs);
        System.out.println("end to setup");

        System.out.println("start to keygen");
        prv = Fscpabe.keygen(pub,msk,myAttrs);
        System.out.println("end to keygen");

        System.out.println("start to enc");
        cphKey = Fscpabe.enc(pub,policy);
        cph = cphKey.cph;
        for(int i=0;i<cphKey.key.length-1;i++)
        {
            System.out.println("m"+i+"="+cphKey.key[i]);
        }
        System.out.println("end to enc");

        System.out.println("start to dec");
        ms = Fscpabe.dec(pub,cph,prv);
        for(int i=0;i<ms.length-1;i++)
        {
            System.out.println("m"+i+"="+ms[i]);
        }
        System.out.println("end to dec");

    }
}
