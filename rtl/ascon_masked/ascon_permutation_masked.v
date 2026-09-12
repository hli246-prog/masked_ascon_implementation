// Masked S-box Construction
// Reference: [2] Groß et al., DOM, Algorithm 1 & Section 4
//            [6] Ascon v1.2 Specification (base S-box definition)


`timescale 1ns / 1ps

`define ROTR64(val, n) ({val[(n)-1:0], val[63:(n)]})

module ascon_permutation_masked (
    input  wire clk,
    input  wire rst_n,
    input  wire start,
    input  wire [3:0]   rounds, 
    
    input  wire [319:0] state_in_s0,
    input  wire [319:0] state_in_s1,
    input  wire [319:0] rand_mask,    
    
    output wire [319:0] state_out_s0,
    output wire [319:0] state_out_s1,
    output reg  done,
    output reg  busy  
);

    reg [319:0] ST_s0;
    reg [319:0] ST_s1;
    reg [3:0] rc;         
    reg [3:0] target_rc;  

    assign state_out_s0 = ST_s0;
    assign state_out_s1 = ST_s1;

    wire [63:0] x0_s0, x1_s0, x2_s0, x3_s0, x4_s0;
    wire [63:0] x0_s1, x1_s1, x2_s1, x3_s1, x4_s1;
    assign {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0} = ST_s0;
    assign {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1} = ST_s1;

    wire [63:0] rand0, rand1, rand2, rand3, rand4;
    assign {rand4, rand3, rand2, rand1, rand0} = rand_mask;

    wire [7:0] rc_lut [0:11];
    assign rc_lut[0]  = 8'hf0; assign rc_lut[1]  = 8'he1;
    assign rc_lut[2]  = 8'hd2; assign rc_lut[3]  = 8'hc3;
    assign rc_lut[4]  = 8'hb4; assign rc_lut[5]  = 8'ha5;
    assign rc_lut[6]  = 8'h96; assign rc_lut[7]  = 8'h87;
    assign rc_lut[8]  = 8'h78; assign rc_lut[9]  = 8'h69;
    assign rc_lut[10] = 8'h5a; assign rc_lut[11] = 8'h4b;

    wire [7:0] round_constant = (rc < 12) ? rc_lut[rc] : 8'h00;
    
    wire [63:0] x2_c_s0 = x2_s0 ^ {56'd0, round_constant};
    wire [63:0] x2_c_s1 = x2_s1;

    wire [63:0] x0_a_s0 = x0_s0 ^ x4_s0;
    wire [63:0] x0_a_s1 = x0_s1 ^ x4_s1;
    wire [63:0] x1_a_s0 = x1_s0;
    wire [63:0] x1_a_s1 = x1_s1;
    wire [63:0] x2_a_s0 = x2_c_s0 ^ x1_s0;
    wire [63:0] x2_a_s1 = x2_c_s1 ^ x1_s1;
    wire [63:0] x3_a_s0 = x3_s0;
    wire [63:0] x3_a_s1 = x3_s1;
    wire [63:0] x4_a_s0 = x4_s0 ^ x3_s0;
    wire [63:0] x4_a_s1 = x4_s1 ^ x3_s1;

    wire [63:0] x0_not_s0 = ~x0_a_s0; wire [63:0] x0_not_s1 = x0_a_s1;
    wire [63:0] x1_not_s0 = ~x1_a_s0; wire [63:0] x1_not_s1 = x1_a_s1;
    wire [63:0] x2_not_s0 = ~x2_a_s0; wire [63:0] x2_not_s1 = x2_a_s1;
    wire [63:0] x3_not_s0 = ~x3_a_s0; wire [63:0] x3_not_s1 = x3_a_s1;
    wire [63:0] x4_not_s0 = ~x4_a_s0; wire [63:0] x4_not_s1 = x4_a_s1;

    wire [63:0] and0_s0, and0_s1;
    wire [63:0] and1_s0, and1_s1;
    wire [63:0] and2_s0, and2_s1;
    wire [63:0] and3_s0, and3_s1;
    wire [63:0] and4_s0, and4_s1;

    masked_and u_and0 (.a_s0(x1_not_s0), .a_s1(x1_not_s1), .b_s0(x2_a_s0), .b_s1(x2_a_s1), .rand_mask(rand0), .c_s0(and0_s0), .c_s1(and0_s1));
    masked_and u_and1 (.a_s0(x2_not_s0), .a_s1(x2_not_s1), .b_s0(x3_a_s0), .b_s1(x3_a_s1), .rand_mask(rand1), .c_s0(and1_s0), .c_s1(and1_s1));
    masked_and u_and2 (.a_s0(x3_not_s0), .a_s1(x3_not_s1), .b_s0(x4_a_s0), .b_s1(x4_a_s1), .rand_mask(rand2), .c_s0(and2_s0), .c_s1(and2_s1));
    masked_and u_and3 (.a_s0(x4_not_s0), .a_s1(x4_not_s1), .b_s0(x0_a_s0), .b_s1(x0_a_s1), .rand_mask(rand3), .c_s0(and3_s0), .c_s1(and3_s1));
    masked_and u_and4 (.a_s0(x0_not_s0), .a_s1(x0_not_s1), .b_s0(x1_a_s0), .b_s1(x1_a_s1), .rand_mask(rand4), .c_s0(and4_s0), .c_s1(and4_s1));

    wire [63:0] chi0_s0 = x0_a_s0 ^ and0_s0; wire [63:0] chi0_s1 = x0_a_s1 ^ and0_s1;
    wire [63:0] chi1_s0 = x1_a_s0 ^ and1_s0; wire [63:0] chi1_s1 = x1_a_s1 ^ and1_s1;
    wire [63:0] chi2_s0 = x2_a_s0 ^ and2_s0; wire [63:0] chi2_s1 = x2_a_s1 ^ and2_s1;
    wire [63:0] chi3_s0 = x3_a_s0 ^ and3_s0; wire [63:0] chi3_s1 = x3_a_s1 ^ and3_s1;
    wire [63:0] chi4_s0 = x4_a_s0 ^ and4_s0; wire [63:0] chi4_s1 = x4_a_s1 ^ and4_s1;

    wire [63:0] s0_c_s0 = chi0_s0 ^ chi4_s0; wire [63:0] s0_c_s1 = chi0_s1 ^ chi4_s1;
    wire [63:0] s1_c_s0 = chi1_s0 ^ chi0_s0; wire [63:0] s1_c_s1 = chi1_s1 ^ chi0_s1;
    wire [63:0] s2_c_s0 = ~chi2_s0;          wire [63:0] s2_c_s1 = chi2_s1;
    wire [63:0] s3_c_s0 = chi3_s0 ^ chi2_s0; wire [63:0] s3_c_s1 = chi3_s1 ^ chi2_s1;
    wire [63:0] s4_c_s0 = chi4_s0;           wire [63:0] s4_c_s1 = chi4_s1;

    wire [63:0] nx0_s0 = s0_c_s0 ^ `ROTR64(s0_c_s0, 19) ^ `ROTR64(s0_c_s0, 28);
    wire [63:0] nx0_s1 = s0_c_s1 ^ `ROTR64(s0_c_s1, 19) ^ `ROTR64(s0_c_s1, 28);
    
    wire [63:0] nx1_s0 = s1_c_s0 ^ `ROTR64(s1_c_s0, 61) ^ `ROTR64(s1_c_s0, 39);
    wire [63:0] nx1_s1 = s1_c_s1 ^ `ROTR64(s1_c_s1, 61) ^ `ROTR64(s1_c_s1, 39);
    
    wire [63:0] nx2_s0 = s2_c_s0 ^ `ROTR64(s2_c_s0, 1)  ^ `ROTR64(s2_c_s0, 6);
    wire [63:0] nx2_s1 = s2_c_s1 ^ `ROTR64(s2_c_s1, 1)  ^ `ROTR64(s2_c_s1, 6);
    
    wire [63:0] nx3_s0 = s3_c_s0 ^ `ROTR64(s3_c_s0, 10) ^ `ROTR64(s3_c_s0, 17);
    wire [63:0] nx3_s1 = s3_c_s1 ^ `ROTR64(s3_c_s1, 10) ^ `ROTR64(s3_c_s1, 17);
    
    wire [63:0] nx4_s0 = s4_c_s0 ^ `ROTR64(s4_c_s0, 7)  ^ `ROTR64(s4_c_s0, 41);
    wire [63:0] nx4_s1 = s4_c_s1 ^ `ROTR64(s4_c_s1, 7)  ^ `ROTR64(s4_c_s1, 41);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ST_s0 <= 320'd0;
            ST_s1 <= 320'd0;
            rc <= 4'd0;
            target_rc <= 4'd0;
            busy <= 1'b0;
            done <= 1'b0;
        end else begin
            done <= 1'b0; 
            if (start && !busy) begin
                ST_s0 <= state_in_s0;
                ST_s1 <= state_in_s1;
                busy <= 1'b1;
                rc <= 4'd12 - rounds;
                target_rc <= 4'd11;
            end else if (busy) begin
                if (rc <= target_rc) begin
                    ST_s0 <= {nx0_s0, nx1_s0, nx2_s0, nx3_s0, nx4_s0};
                    ST_s1 <= {nx0_s1, nx1_s1, nx2_s1, nx3_s1, nx4_s1};
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
