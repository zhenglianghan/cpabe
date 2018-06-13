package co.zlh.bswabe;

import it.unisa.dia.gas.jpbc.Element;

public class BswabePrvComp {
	/* these actually get serialized */
	String attr;
	Element d;					/* G_2 */ //Dj
	Element dp;				/* G_2 */ //Dj`
	
	/* only used during dec */
	int used;
	Element z;					/* G_1 */
	Element zp;				/* G_1 */
}
