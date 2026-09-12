`timescale 1ns / 1ps

module tb_masked_and;

    reg  [63:0] a_s0, a_s1;
    reg  [63:0] b_s0, b_s1;
    reg  [63:0] rand_mask;
    wire [63:0] c_s0, c_s1;
    
    reg  [63:0] a_orig, b_orig;
    reg  [63:0] c_reconstructed;
    
    integer i;
    integer error_count;

    masked_and uut (
        .a_s0(a_s0),
        .a_s1(a_s1),
        .b_s0(b_s0),
        .b_s1(b_s1),
        .rand_mask(rand_mask),
        .c_s0(c_s0),
        .c_s1(c_s1)
    );

    initial begin
        error_count = 0;
        
        for (i = 0; i < 10000; i = i + 1) begin
            a_orig = {$random, $random};
            b_orig = {$random, $random};
            
            rand_mask = {$random, $random};
            
            a_s0 = {$random, $random};
            a_s1 = a_orig ^ a_s0;
            
            b_s0 = {$random, $random};
            b_s1 = b_orig ^ b_s0;
            
            #5; 
            
            c_reconstructed = c_s0 ^ c_s1;
            
            if (c_reconstructed !== (a_orig & b_orig)) begin
                $display("ERROR at test %0d: a=%h, b=%h", i, a_orig, b_orig);
                $display("Expected: %h", (a_orig & b_orig));
                $display("Got     : %h", c_reconstructed);
                error_count = error_count + 1;
            end
        end
        
        if (error_count == 0) begin
            $display("SUCCESS: All 10000 randomized masked AND tests passed");
        end else begin
            $display("FAILED with %0d errors.", error_count);
        end
        
        $stop;
    end

endmodule