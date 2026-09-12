`timescale 1ns / 1ps

module tb_masked_permutation;

    reg clk;
    reg rst_n;

    always #5 clk = ~clk; // 100MHz 

    reg start;
    reg [3:0] rounds;
    
    reg  [319:0] state_in_orig;
    wire [319:0] state_out_orig;
    wire done_orig;
    wire busy_orig;

    ascon_permutation u_perm_orig (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .rounds(rounds),
        .state_in(state_in_orig),
        .state_out(state_out_orig),
        .done(done_orig),
        .busy(busy_orig)
    );

    reg  [319:0] state_in_s0;
    reg  [319:0] state_in_s1;
    reg  [319:0] rand_mask;
    wire [319:0] state_out_s0;
    wire [319:0] state_out_s1;
    wire done_masked;
    wire busy_masked;

    ascon_permutation_masked u_perm_masked (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .rounds(rounds),
        .state_in_s0(state_in_s0),
        .state_in_s1(state_in_s1),
        .rand_mask(rand_mask),
        .state_out_s0(state_out_s0),
        .state_out_s1(state_out_s1),
        .done(done_masked),
        .busy(busy_masked)
    );

    always @(posedge clk) begin
        rand_mask <= { 
            $random, $random, $random, $random, $random,
            $random, $random, $random, $random, $random 
        };
    end

  
    function [319:0] get_rand_320;
        input integer dummy_input; 
        begin
            get_rand_320 = { 
                $random, $random, $random, $random, $random,
                $random, $random, $random, $random, $random 
            };
        end
    endfunction


    integer i;
    integer error_count = 0;
    reg [319:0] state_reconstructed;


    task run_test(input [3:0] test_rounds, input integer test_num);
        begin
            for (i = 0; i < test_num; i = i + 1) begin
                
                state_in_orig = get_rand_320(0);
                           
                state_in_s0   = get_rand_320(0);
                
                state_in_s1   = state_in_orig ^ state_in_s0;
                
                rounds = test_rounds;
                
                @(posedge clk);
                start = 1;
                @(posedge clk);
                start = 0;
                
                wait (done_orig && done_masked);
                @(posedge clk); 
                
                state_reconstructed = state_out_s0 ^ state_out_s1;

                if (state_reconstructed !== state_out_orig) begin

                    $display("ERROR at Test Iteration %0d (Rounds = %0d)", i, test_rounds);
                    $display("Expected Orig Out : %x", state_out_orig);
                    $display("Masked Recon Out  : %x", state_reconstructed);
                    $display("Share 0 Out       : %x", state_out_s0);
                    $display("Share 1 Out       : %x", state_out_s1);

                    error_count = error_count + 1;
                end
            end
            
            if (error_count == 0)
                $display("SUCCESS: %0d iterations for %0d rounds passed", test_num, test_rounds);
            else
                $display("FAILED: %0d rounds had %0d errors.", test_rounds, error_count);
        end
    endtask


    initial begin

        clk = 0;
        rst_n = 0;
        start = 0;
        rounds = 0;
        state_in_orig = 0;
        state_in_s0 = 0;
        state_in_s1 = 0;
        
        $display("Starting Masked Permutation Tests...");


        #20;
        rst_n = 1;
        #20;

        $display("--- Testing 1 Round ---");
        error_count = 0;
        run_test(4'd1, 1000); 

        $display("--- Testing 6 Rounds ---");
        error_count = 0;
        run_test(4'd6, 1000); 

        $display("--- Testing 12 Rounds ---");
        error_count = 0;
        run_test(4'd12, 1000); 

        if (error_count == 0) begin
            $display("ALL PERMUTATION TESTS PASSED PERFECTLY!");
        end else begin
            $display("PERMUTATION TESTS FAILED WITH ERRORS!");
        end
        
        $stop;
    end

endmodule