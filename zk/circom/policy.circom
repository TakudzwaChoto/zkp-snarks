pragma circom 2.1.5;
include "circomlib/circuits/poseidon.circom";

// Convert boolean to field
template BoolToField() {
    signal input in;
    signal output out;
    out <== in * 1;
}

// Checks if input slice equals a constant token
// tokenLen is the fixed length of the token
template MatchToken(tokenLen, tokenVals) {
    signal input slice[tokenLen]; // private slice of the prompt bytes (field elems 0..255)
    signal output isMatch;        // boolean (0/1)

    var i;
    signal eqs[tokenLen];
    for (i = 0; i < tokenLen; i++) {
        // eq if slice[i] == tokenVals[i]
        eqs[i] <== 1 - (slice[i] - tokenVals[i]) * (slice[i] - tokenVals[i]);
        // This is not a strict eq check; for practical use, replace with explicit comparator gadget.
    }

    // AND-reduce eqs
    signal acc[tokenLen];
    acc[0] <== eqs[0];
    for (i = 1; i < tokenLen; i++) {
        acc[i] <== acc[i-1] * eqs[i];
    }
    // Convert to boolean-ish 0/1
    signal b;
    b <== acc[tokenLen-1];
    isMatch <== b;
}

// Sliding window substring search for two tokens: "admin" and "bypass"
// For production, replace with a DFA-based checker and robust equality.
template PolicyCheck(N) {
    // Private inputs: prompt as N bytes (0..255)
    signal input prompt[N];

    // Public inputs
    signal input commitment; // Poseidon hash of prompt array
    signal input threshold;  // not used in this minimal circuit (kept for future policy scoring)

    // Hash and compare to commitment
    component hasher = Poseidon(N);
    var i;
    for (i = 0; i < N; i++) {
        hasher.inputs[i] <== prompt[i];
    }
    hasher.out === commitment;

    // Tokens as constants (ascii)
    var ADMIN_LEN = 5;
    var BYPASS_LEN = 6;
    var adminTok[5] = [97,100,109,105,110];       // "admin"
    var bypassTok[6] = [98,121,112,97,115,115];   // "bypass"

    // Sliding window matches
    signal anyAdmin;
    anyAdmin <== 0;
    signal anyBypass;
    anyBypass <== 0;

    // Check admin
    for (i = 0; i <= N - ADMIN_LEN; i++) {
        component m = MatchToken(ADMIN_LEN, adminTok);
        var j;
        for (j = 0; j < ADMIN_LEN; j++) {
            m.slice[j] <== prompt[i + j];
        }
        anyAdmin <== anyAdmin + m.isMatch;
    }

    // Check bypass
    for (i = 0; i <= N - BYPASS_LEN; i++) {
        component m2 = MatchToken(BYPASS_LEN, bypassTok);
        var k;
        for (k = 0; k < BYPASS_LEN; k++) {
            m2.slice[k] <== prompt[i + k];
        }
        anyBypass <== anyBypass + m2.isMatch;
    }

    // Enforce that no banned token occurs
    // For simplicity we require sums == 0
    anyAdmin === 0;
    anyBypass === 0;
}