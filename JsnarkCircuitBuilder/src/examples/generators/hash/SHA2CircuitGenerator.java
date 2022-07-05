/*******************************************************************************
s * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators.hash;

import java.math.BigInteger;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;

public class SHA2CircuitGenerator extends CircuitGenerator {

	private Wire[] inputWires;
	private SHA256Gadget sha2Gadget;
	private Wire[] leafWires;
	private int leafNumOfWords = 16;
	private int leafWordBitWidth = 32;

	public SHA2CircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		
		// assuming the circuit input will be 64 bytes
		//inputWires = createInputWireArray(64);
		leafWires = createProverWitnessWireArray(leafNumOfWords, "Secret Leaf");
		inputWires = new WireArray(leafWires).getBits(leafWordBitWidth).asArray();
		
		// this gadget is not applying any padding.
		//if we change paddingRequired, then output is same
		//sha2Gadget = new SHA256Gadget(inputWires, 8, 64, false, true);
		sha2Gadget = new SHA256Gadget(inputWires, 1, 64, false, true);
		Wire[] digest = sha2Gadget.getOutputWires();
		makeOutputArray(digest, "digest");
		
		// ======================================================================
		// To see how padding can be done, and see how the gadget library will save constraints automatically, 
		// try the snippet below instead.
		/*
			inputWires = createInputWireArray(3); 	// 3-byte input
			sha2Gadget = new SHA256Gadget(inputWires, 8, 3, false, true);
			Wire[] digest = sha2Gadget.getOutputWires();
			makeOutputArray(digest, "digest");
		*/
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		// String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		// for (int i = 0; i < inputWires.length; i++) {
		// 	evaluator.setWireValue(inputWires[i], inputStr.charAt(i));
		// }
		circuitEvaluator.setWireValue(leafWires[0], new BigInteger("2005877056"));
		circuitEvaluator.setWireValue(leafWires[1], new BigInteger("3070462378"));
		circuitEvaluator.setWireValue(leafWires[2], new BigInteger("1317841443"));
		circuitEvaluator.setWireValue(leafWires[3], new BigInteger("304683098"));
		circuitEvaluator.setWireValue(leafWires[4], new BigInteger("2932194771"));
		circuitEvaluator.setWireValue(leafWires[5], new BigInteger("3240151078"));
		circuitEvaluator.setWireValue(leafWires[6], new BigInteger("3316731475"));
		circuitEvaluator.setWireValue(leafWires[7], new BigInteger("818354926"));
		circuitEvaluator.setWireValue(leafWires[8], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[9], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[10], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[11], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[12], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[13], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[14], new BigInteger("2222222222"));
		circuitEvaluator.setWireValue(leafWires[15], new BigInteger("2222222222"));
	}

	public static void main(String[] args) throws Exception {
		SHA2CircuitGenerator generator = new SHA2CircuitGenerator("sha_256");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}