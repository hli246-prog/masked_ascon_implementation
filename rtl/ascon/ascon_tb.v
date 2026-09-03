`timescale 1ns / 1ps

module ascon_tb;

    reg clk;
    reg rst_n;
    reg start;
    reg encrypt;
    reg [127:0] key;
    reg [127:0] nonce;
    
    reg [63:0] ad_data;
    reg ad_valid;
    reg ad_last;
    
    reg [63:0] msg_data;
    reg msg_valid;
    reg msg_last;
    reg [2:0] msg_bytes;
    reg [127:0] tag_in;
    
    wire [63:0] out_data;
    wire out_valid;
    wire out_last;
    wire [127:0] tag_out;
    wire auth_pass;
    wire busy;
    wire done;

    ascon_top u_top (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .encrypt(encrypt),
        .key(key),
        .nonce(nonce),
        .ad_data(ad_data),
        .ad_valid(ad_valid),
        .ad_last(ad_last),
        .msg_data(msg_data),
        .msg_valid(msg_valid),
        .msg_last(msg_last),
        .msg_bytes(msg_bytes),
        .tag_in(tag_in),
        .out_data(out_data),
        .out_valid(out_valid),
        .out_last(out_last),
        .tag_out(tag_out),
        .auth_pass(auth_pass),
        .busy(busy),
        .done(done)
    );

    initial begin
        clk = 0;
        forever #5 clk = ~clk; 
    end

    task send_ad;
        input [63:0] data;
        input last;
        input [2:0] bytes;
        begin
            @(posedge clk);
            ad_data   <= data; 
            ad_valid  <= 1'b1; 
            ad_last   <= last; 
            msg_bytes <= bytes;
            
            while (u_top.perm_start == 1'b0) @(posedge clk); 
            ad_valid  <= 1'b0;
            
            while (u_top.perm_busy == 1'b1 || u_top.perm_start == 1'b1) @(posedge clk);
        end
    endtask

    task send_msg;
        input [63:0] data;
        input last;
        input [2:0] bytes;
        input is_enc;
        begin
            @(posedge clk);
            msg_data  <= data; 
            msg_valid <= 1'b1; 
            msg_last  <= last; 
            msg_bytes <= bytes;
            
            while (out_valid == 1'b0) @(posedge clk);
            
            if (is_enc) $display("CT Block: %X", out_data);
            else        $display("PT Block: %X", out_data);
            
            msg_valid <= 1'b0;
            
            if (!last) begin
                while (u_top.perm_busy == 1'b1 || u_top.perm_start == 1'b1) @(posedge clk);
            end
        end
    endtask

    initial begin
        rst_n = 0;
        start = 0; encrypt = 0;
        ad_valid = 0; ad_last = 0; ad_data = 0;
        msg_valid = 0; msg_last = 0; msg_data = 0; msg_bytes = 0; tag_in = 0;

        #20 rst_n = 1;
        #20;

        $display("Starting Ascon-128 Test Vectors");

        // TEST 1: Encrypt Mode
        $display("\n---> [TEST 1] Count = 715 : Encrypt Mode");
        key   <= 128'h000102030405060708090A0B0C0D0E0F;
        nonce <= 128'h000102030405060708090A0B0C0D0E0F;
        encrypt <= 1;
        
        @(posedge clk); start <= 1;
        @(posedge clk); start <= 0;

        wait(u_top.state == 4'd4); 
        @(posedge clk);

        send_ad(64'h0001020304050607, 0, 3'd0);
        send_ad(64'h08090A0B0C0D0E0F, 0, 3'd0);
        send_ad(64'h1011121314000000, 1, 3'd5);

        send_msg(64'h0001020304050607, 0, 3'd0, 1);
        send_msg(64'h08090A0B0C0D0E0F, 0, 3'd0, 1);
        send_msg(64'h1011121314000000, 1, 3'd5, 1);

        wait(done == 1'b1);
        $display("Tag (Expected: 4590B4B7524D50CE73DF27604183A58B): %X", tag_out);
        #50;

        // TEST 2: Decrypt Mode
        $display("\n---> [TEST 2] Count = 715 : Decrypt Mode");
        encrypt <= 0;
        tag_in <= 128'h4590B4B7524D50CE73DF27604183A58B; 
        
        @(posedge clk); start <= 1;
        @(posedge clk); start <= 0;

        wait(u_top.state == 4'd4); 
        @(posedge clk);

        send_ad(64'h0001020304050607, 0, 3'd0);
        send_ad(64'h08090A0B0C0D0E0F, 0, 3'd0);
        send_ad(64'h1011121314000000, 1, 3'd5);
        
        send_msg(64'h74EA9BA2635DCBAA, 0, 3'd0, 0);
        send_msg(64'h400A5C24E4970400, 0, 3'd0, 0);
        send_msg(64'hCA78DE8241000000, 1, 3'd5, 0);
        
        wait(done == 1'b1);
        $display("Auth Pass? (Expected: 1): %b", auth_pass);
        #50;

        // TEST 3: Encrypt Mode (Boundary test)
        $display("\n---> [TEST 3] Count = 1 : Encrypt Mode (Boundary test)");
        encrypt <= 1;
        
        @(posedge clk); start <= 1;
        @(posedge clk); start <= 0;

        wait(u_top.state == 4'd4); 
        @(posedge clk);

        send_msg(64'h0, 1, 3'd0, 1);
        
        wait(done == 1'b1);
        $display("Tag (Expected: E355159F292911F794CB1432A0103A8A): %X", tag_out);

        $display("                  TEST COMPLETED");
        $finish;
    end
endmodule