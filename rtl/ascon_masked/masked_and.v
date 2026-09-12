// Masked AND Gate 
// Reference: [11] Ishai-Sahai-Wagner, CRYPTO 2003, Section 3
//            [2]  Groß et al., DOM, Section 4.2 (hardware adaptation)

`timescale 1ns / 1ps

module masked_and (
    input  wire [63:0] a_s0,
    input  wire [63:0] a_s1,
    input  wire [63:0] b_s0,
    input  wire [63:0] b_s1,
    input  wire [63:0] rand_mask,
    output wire [63:0] c_s0,
    output wire [63:0] c_s1
);

    assign c_s0 = (a_s0 & b_s0) ^ rand_mask;
    
    assign c_s1 = (a_s0 & b_s1) ^ (a_s1 & b_s0) ^ (a_s1 & b_s1) ^ rand_mask;

endmodule
