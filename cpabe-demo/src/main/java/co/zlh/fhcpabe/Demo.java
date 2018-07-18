package co.zlh.fhcpabe;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;

public class Demo {
    //static String[] attr = {"a","b","c","d","e","f"};
    static String[] attr = {"0","2"};
    //static String policy= "a b 2of2 d 2of2 e 2of2 f g 2of3" ;
    static String policy= "2 3 1of2 0 1 3of3" ;
    public static void main(String[] args) throws Exception {
        FhcpabePub pub = new FhcpabePub();
        FhcpabeMsk msk = new FhcpabeMsk();
        FhcpabePrv prv;
        FhcpabeCph cph;
        FhcpabeCphKey cphKey;
        ArrayList<Element> cks = new ArrayList<Element>();

        long startTime=System.currentTimeMillis();   //获取开始时间
        System.out.println("start to setup");
        Fhcpabe.setup(pub,msk);
        System.out.println("end to setup");

        System.out.println("start to keygen");
        prv = Fhcpabe.keygen(pub,msk,attr);
        System.out.println("end to keygen");

        System.out.println("start to enc");
        cphKey = Fhcpabe.enc(pub,policy);
        cph = cphKey.cph;
        cks = cphKey.cks;
        System.out.println("enc cks are:");
        for(int i = 0;i<cks.size();i++)
        {
            String out = "ck" + i + "=" +cks.get(i);
            System.out.println(out);
        }
        System.out.println("end to enc");

        System.out.println("start to dec");
        Fhcpabe.dec(pub,prv,cph);
        System.out.println("end to dec");
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("程序运行时间： "+(endTime-startTime)+"ms");

        System.out.println("dec cks are:");
        int j = 0;
        printcks(cph.p,j);
    }



    public static void printcks(FhcpabePolicy p ,int j)
    {
        if(!p.satisfiable && p.ck !=null)
        {
            j++;
        }
        if(p.satisfiable && p.ck != null)
        {
            String out = "ck" + j + "=" + p.ck;
            System.out.println(out);
            j++;
        }
        if(p.children != null && p.children.length>=0)
        {
            for(int i = 0;i<p.children.length;i++)
            {
                printcks(p.children[i],j);
            }
        }
    }
}
