pragma circom 2.1.5;
include "circomlib/circuits/poseidon.circom";

// Convert boolean to field
template BoolToField() {
    signal input in;
    signal output out;
    out <== in * 1;
}

// Enhanced token matcher with better equality checking
template MatchToken(tokenLen, tokenVals) {
    signal input slice[tokenLen]; // private slice of the prompt bytes (field elems 0..255)
    signal output isMatch;        // boolean (0/1)

    var i;
    signal eqs[tokenLen];
    for (i = 0; i < tokenLen; i++) {
        // More robust equality check
        eqs[i] <== 1 - (slice[i] - tokenVals[i]) * (slice[i] - tokenVals[i]);
    }

    // AND-reduce eqs
    signal acc[tokenLen];
    acc[0] <== eqs[0];
    for (i = 1; i < tokenLen; i++) {
        acc[i] <== acc[i-1] * eqs[i];
    }
    isMatch <== acc[tokenLen-1];
}

// Policy scoring component
template PolicyScoring(N, numTokens) {
    signal input prompt[N];
    signal input tokenMatches[numTokens]; // 0/1 for each token
    signal input weights[numTokens];      // weight for each token (0..255)
    signal output safetyScore;           // 0..255, higher = safer
    
    var i;
    var totalWeight = 0;
    var penalty = 0;
    
    // Calculate total weight and penalty
    for (i = 0; i < numTokens; i++) {
        totalWeight <== totalWeight + weights[i];
        penalty <== penalty + (tokenMatches[i] * weights[i]);
    }
    
    // Safety score: 255 - penalty (clamped to 0..255)
    signal clampedPenalty;
    clampedPenalty <== penalty > 255 ? 255 : penalty;
    safetyScore <== 255 - clampedPenalty;
}

// Enhanced policy checker with configurable tokens and scoring
template PolicyCheck(N, numTokens) {
    // Private inputs: prompt as N bytes (0..255)
    signal input prompt[N];

    // Public inputs
    signal input commitment; // Poseidon hash of prompt array
    signal input threshold;  // minimum safety score (0..255)
    signal input tokenWeights[numTokens]; // weights for each token

    // Hash and compare to commitment
    component hasher = Poseidon(N);
    var i;
    for (i = 0; i < N; i++) {
        hasher.inputs[i] <== prompt[i];
    }
    hasher.out === commitment;

    // Define banned tokens (ASCII values)
    var ADMIN_LEN = 5;
    var BYPASS_LEN = 6;
    var SYSTEM_LEN = 6;
    var ROLE_LEN = 4;
    
    var adminTok[5] = [97,100,109,105,110];       // "admin"
    var bypassTok[6] = [98,121,112,97,115,115];   // "bypass"
    var systemTok[6] = [115,121,115,116,101,109]; // "system"
    var roleTok[4] = [114,111,108,101];           // "role"

    // Token matching results
    signal adminMatch;
    signal bypassMatch;
    signal systemMatch;
    signal roleMatch;
    
    adminMatch <== 0;
    bypassMatch <== 0;
    systemMatch <== 0;
    roleMatch <== 0;

    // Check admin token
    for (i = 0; i <= N - ADMIN_LEN; i++) {
        component m = MatchToken(ADMIN_LEN, adminTok);
        var j;
        for (j = 0; j < ADMIN_LEN; j++) {
            m.slice[j] <== prompt[i + j];
        }
        adminMatch <== adminMatch + m.isMatch;
    }

    // Check bypass token
    for (i = 0; i <= N - BYPASS_LEN; i++) {
        component m2 = MatchToken(BYPASS_LEN, bypassTok);
        var k;
        for (k = 0; k < BYPASS_LEN; k++) {
            m2.slice[k] <== prompt[i + k];
        }
        bypassMatch <== bypassMatch + m2.isMatch;
    }

    // Check system token
    for (i = 0; i <= N - SYSTEM_LEN; i++) {
        component m3 = MatchToken(SYSTEM_LEN, systemTok);
        var l;
        for (l = 0; l < SYSTEM_LEN; l++) {
            m3.slice[l] <== prompt[i + l];
        }
        systemMatch <== systemMatch + m3.isMatch;
    }

    // Check role token
    for (i = 0; i <= N - ROLE_LEN; i++) {
        component m4 = MatchToken(ROLE_LEN, roleTok);
        var m;
        for (m = 0; m < ROLE_LEN; m++) {
            m4.slice[m] <== prompt[i + m];
        }
        roleMatch <== roleMatch + m4.isMatch;
    }

    // Convert matches to binary (0/1)
    signal adminBinary;
    signal bypassBinary;
    signal systemBinary;
    signal roleBinary;
    
    adminBinary <== adminMatch > 0 ? 1 : 0;
    bypassBinary <== bypassMatch > 0 ? 1 : 0;
    systemBinary <== systemMatch > 0 ? 1 : 0;
    roleBinary <== roleMatch > 0 ? 1 : 0;

    // Calculate safety score
    component scoring = PolicyScoring(N, numTokens);
    var j;
    for (j = 0; j < N; j++) {
        scoring.prompt[j] <== prompt[j];
    }
    scoring.tokenMatches[0] <== adminBinary;
    scoring.tokenMatches[1] <== bypassBinary;
    scoring.tokenMatches[2] <== systemBinary;
    scoring.tokenMatches[3] <== roleBinary;
    
    for (j = 0; j < numTokens; j++) {
        scoring.weights[j] <== tokenWeights[j];
    }

    // Enforce threshold constraint
    scoring.safetyScore >= threshold;
}

// Main circuit component
component main { public [commitment, threshold] } = PolicyCheck(128, 4);