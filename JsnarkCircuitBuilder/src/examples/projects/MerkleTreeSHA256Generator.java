package examples.projects;

import java.math.BigInteger;
import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.projects.MerkleTreePathGadget;
import examples.gadgets.hash.SHA256Gadget;

public class MerkleTreeSHA256Generator extends CircuitGenerator {

	private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;
	private Wire[] leafWires;
	private int leafNumOfWords = 10;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = 8;
	private MerkleTreePathGadget merkleTreeGadget;
	
	public MerkleTreeSHA256Generator(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		
		/** declare inputs **/
		
		publicRootWires = createInputWireArray(hashDigestDimension, "Input Merkle Tree Root");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		directionSelector = createProverWitnessWire("Direction selector");
		leafWires = createProverWitnessWireArray(leafNumOfWords, "Secret Leaf");

		/** connect gadget **/

		merkleTreeGadget = new MerkleTreePathGadget(
				directionSelector, leafWires, intermediateHasheWires, leafWordBitWidth, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();
		
		/** Now compare the actual root with the public known root **/
		Wire errorAccumulator = getZeroWire();
		for(int i = 0; i < hashDigestDimension; i++){
			Wire diff = actualRoot[i].sub(publicRootWires[i]);
			Wire check = diff.checkNonZero();
			errorAccumulator = errorAccumulator.add(check);
		}
		
		makeOutputArray(actualRoot, "Computed Root");
		
		/** Expected mismatch here if the sample input below is tried**/
		makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

		circuitEvaluator.setWireValue(publicRootWires[0], new BigInteger("3555412827"));
		circuitEvaluator.setWireValue(publicRootWires[1], new BigInteger("2623498857"));
		circuitEvaluator.setWireValue(publicRootWires[2], new BigInteger("1009556847"));
		circuitEvaluator.setWireValue(publicRootWires[3], new BigInteger("3412945572"));
		circuitEvaluator.setWireValue(publicRootWires[4], new BigInteger("3198149492"));
		circuitEvaluator.setWireValue(publicRootWires[5], new BigInteger("3422777958"));
		circuitEvaluator.setWireValue(publicRootWires[6], new BigInteger("2675018006"));
		circuitEvaluator.setWireValue(publicRootWires[7], new BigInteger("1896274658"));
		
		circuitEvaluator.setWireValue(directionSelector, new BigInteger("3"));

		// witness: co-path
		for(int i=0; i<hashDigestDimension; i++) { circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("1111111111")); }
		for(int i=hashDigestDimension; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("2222222222")); }
		
		for(int i=0; i<leafNumOfWords; i++){ circuitEvaluator.setWireValue(leafWires[i], Integer.MAX_VALUE); }
	}
	
	public static void main(String[] args) throws Exception {
		
		MerkleTreeSHA256Generator generator = new MerkleTreeSHA256Generator("tree_2", 2);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}

}
