// Ascon Permutation Core
// Reference: [6] Ascon v1.2 Specification, Section 2.3-2.5
// - S-box: 5-bit substitution per Table 1 of the spec
// - Linear layer: bitwise rotation XOR structure per Section 2.4
// - Round constants: hardcoded per Table 3 (12 rounds for Ascon-128)
// All logic below is a direct transcription of the mathematical
// definition; no optimization or alternative formulation is applied.

`timescale 1ns / 1ps

`define ROTR64(val, n) ({val[(n)-1:0], val[63:(n)]})

module ascon_permutation (
    input wire clk,
    input wire rst_n,
    input wire start,
    input wire [3:0] rounds, 
    input wire [319:0] state_in,
    output wire [319:0] state_out,
    output reg done,
    output reg busy  
);

    reg [319:0] ST;
    reg [3:0] rc;         
    reg [3:0] target_rc;  

    assign state_out = ST;

    wire [63:0] x0, x1, x2, x3, x4;
    assign {x0, x1, x2, x3, x4} = ST;

    wire [7:0] rc_lut [0:11];
    assign rc_lut[0]  = 8'hf0;
    assign rc_lut[1]  = 8'he1;
    assign rc_lut[2]  = 8'hd2;
    assign rc_lut[3]  = 8'hc3;
    assign rc_lut[4]  = 8'hb4;
    assign rc_lut[5]  = 8'ha5;
    assign rc_lut[6]  = 8'h96;
    assign rc_lut[7]  = 8'h87;
    assign rc_lut[8]  = 8'h78;
    assign rc_lut[9]  = 8'h69;
    assign rc_lut[10] = 8'h5a;
    assign rc_lut[11] = 8'h4b;

    wire [7:0] round_constant = (rc < 12) ? rc_lut[rc] : 8'h00;
    
    wire [63:0] x2_c = x2 ^ {56'd0, round_constant};

    wire [63:0] x0_a = x0 ^ x4;
    wire [63:0] x1_a = x1;
    wire [63:0] x2_a = x2_c ^ x1;
    wire [63:0] x3_a = x3;
    wire [63:0] x4_a = x4 ^ x3;

    wire [63:0] chi0 = x0_a ^ ((~x1_a) & x2_a);
    wire [63:0] chi1 = x1_a ^ ((~x2_a) & x3_a);
    wire [63:0] chi2 = x2_a ^ ((~x3_a) & x4_a);
    wire [63:0] chi3 = x3_a ^ ((~x4_a) & x0_a);
    wire [63:0] chi4 = x4_a ^ ((~x0_a) & x1_a);

    wire [63:0] s0_c = chi0 ^ chi4;
    wire [63:0] s1_c = chi1 ^ chi0;
    wire [63:0] s2_c = ~chi2;
    wire [63:0] s3_c = chi3 ^ chi2;
    wire [63:0] s4_c = chi4;

    wire [63:0] nx0 = s0_c ^ `ROTR64(s0_c, 19) ^ `ROTR64(s0_c, 28);
    wire [63:0] nx1 = s1_c ^ `ROTR64(s1_c, 61) ^ `ROTR64(s1_c, 39);
    wire [63:0] nx2 = s2_c ^ `ROTR64(s2_c, 1)  ^ `ROTR64(s2_c, 6);
    wire [63:0] nx3 = s3_c ^ `ROTR64(s3_c, 10) ^ `ROTR64(s3_c, 17);
    wire [63:0] nx4 = s4_c ^ `ROTR64(s4_c, 7)  ^ `ROTR64(s4_c, 41);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ST <= 320'd0;
            rc <= 4'd0;
            target_rc <= 4'd0;
            busy <= 1'b0;
            done <= 1'b0;
        end else begin
            done <= 1'b0; 
            if (start && !busy) begin
                ST <= state_in;
                busy <= 1'b1;
                rc <= 4'd12 - rounds;
                target_rc <= 4'd11;
            end else if (busy) begin
                if (rc <= target_rc) begin
                    ST <= {nx0, nx1, nx2, nx3, nx4};
                    if (rc == target_rc) begin
                        busy <= 1'b0;
                        done <= 1'b1; 
                    end else begin
                        rc <= rc + 1'b1;
                    end
                end
            end
        end
    end
endmodule
