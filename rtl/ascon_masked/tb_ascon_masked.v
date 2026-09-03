`timescale 1ns / 1ps

module tb_ascon_masked;

    reg clk;
    reg rst_n;
    
    reg start;
    reg encrypt;
    reg [127:0] key;
    reg [127:0] nonce;
    reg [63:0]  ad_data;
    reg ad_valid;
    reg ad_last;
    reg [2:0]   ad_bytes; 
    reg [63:0]  msg_data;
    reg msg_valid;
    reg msg_last;
    reg [2:0]   msg_bytes;
    reg [127:0] tag_in;
    
    wire [63:0] out_data;
    wire out_valid;
    wire out_last;
    wire [127:0] tag_out;
    wire auth_pass;
    wire busy;
    wire done;

    reg [319:0] perm_rand_mask;
    reg [63:0]  rand_key1;
    reg [63:0]  rand_key2;
    reg [63:0]  rand_dec;
    reg [63:0]  rand_dec_last;

    ascon_top_masked u_top (
        .clk(clk), .rst_n(rst_n), .start(start), .encrypt(encrypt),
        .key(key), .nonce(nonce),
        .ad_data(ad_data), .ad_valid(ad_valid), .ad_last(ad_last), .ad_bytes(ad_bytes),
        .msg_data(msg_data), .msg_valid(msg_valid), .msg_last(msg_last),
        .msg_bytes(msg_bytes), .tag_in(tag_in),
        .out_data(out_data), .out_valid(out_valid), .out_last(out_last),
        .tag_out(tag_out), .auth_pass(auth_pass),
        .busy(busy), .done(done),
        .perm_rand_mask(perm_rand_mask),
        .rand_key1(rand_key1), .rand_key2(rand_key2), .rand_dec(rand_dec),
        .rand_dec_last(rand_dec_last)
    );

    always #5 clk = ~clk;

    always @(posedge clk) begin
        perm_rand_mask[31:0]    <= $random;
        perm_rand_mask[63:32]   <= $random;
        perm_rand_mask[95:64]   <= $random;
        perm_rand_mask[127:96]  <= $random;
        perm_rand_mask[159:128] <= $random;
        perm_rand_mask[191:160] <= $random;
        perm_rand_mask[223:192] <= $random;
        perm_rand_mask[255:224] <= $random;
        perm_rand_mask[287:256] <= $random;
        perm_rand_mask[319:288] <= $random;

        rand_key1[31:0]  <= $random;
        rand_key1[63:32] <= $random;
        rand_key2[31:0]  <= $random;
        rand_key2[63:32] <= $random;
        rand_dec[31:0]   <= $random;
        rand_dec[63:32]  <= $random;
        
        rand_dec_last[31:0]  <= $random;
        rand_dec_last[63:32] <= $random;
    end

    task send_ad_block(input [63:0] b_data, input b_last, input [2:0] b_bytes);
    reg done_flag;
    begin
        ad_valid = 1; ad_data = b_data; ad_last = b_last; ad_bytes = b_bytes;
        done_flag = 0;
        
        while (done_flag == 0) begin
            @(posedge clk);
            if (u_top.perm_start == 1'b1) begin
                done_flag = 1;
            end
        end
        ad_valid = 0;
    end
    endtask

    task send_msg_block(input [63:0] b_data, input b_last, input [2:0] b_bytes);
    reg done_flag;
    begin
        msg_valid = 1; msg_data = b_data; msg_last = b_last; msg_bytes = b_bytes;
        done_flag = 0;
        
        while (done_flag == 0) begin
            @(posedge clk);
            if (u_top.out_valid == 1'b1) begin
                done_flag = 1;
            end
        end
        msg_valid = 0;
    end
    endtask

    integer error_cnt = 0;

    task run_test(input integer id, input reg is_enc);
        reg [31:0] ad_len;
        reg [31:0] pt_len;
        reg [127:0] exp_tag;
        
        reg [8191:0] t_ad;
        reg [8191:0] t_pt;
        reg [8191:0] t_ct;       
        reg [8191:0] active_msg; 

        reg [63:0] block;
        integer i, j, rem, idx;
        begin
            get_tv(id, ad_len, pt_len, exp_tag, t_ad, t_pt, t_ct);
            tag_in = exp_tag; 
            
            if (is_enc) active_msg = t_pt;
            else        active_msg = t_ct;
            
            @(posedge clk);
            start = 1; encrypt = is_enc;
            @(posedge clk);
            start = 0;

            wait(u_top.state == 4);

            if (ad_len > 0) begin
                for (i = 0; i < ad_len; i = i + 8) begin
                    rem = ad_len - i;
                    if (rem > 8) rem = 8;
                    for (j = 0; j < 8; j = j + 1) begin
                        if (j < rem) begin
                            idx = (ad_len - 1 - (i + j)) * 8;
                            block[63 - j*8 -: 8] = t_ad[idx +: 8];
                        end else begin
                            block[63 - j*8 -: 8] = 8'h00;
                        end
                    end
                    send_ad_block(block, (rem < 8), (rem < 8) ? rem[2:0] : 3'd0);
                end
                if (ad_len % 8 == 0) send_ad_block(64'd0, 1, 3'd0);
            end

            if (pt_len > 0) begin
                for (i = 0; i < pt_len; i = i + 8) begin
                    rem = pt_len - i;
                    if (rem > 8) rem = 8;
                    for (j = 0; j < 8; j = j + 1) begin
                        if (j < rem) begin
                            idx = (pt_len - 1 - (i + j)) * 8;
                            block[63 - j*8 -: 8] = active_msg[idx +: 8]; 
                        end else begin
                            block[63 - j*8 -: 8] = 8'h00;
                        end
                    end
                    send_msg_block(block, (rem < 8), (rem < 8) ? rem[2:0] : 3'd0);
                end
                if (pt_len % 8 == 0) send_msg_block(64'd0, 1, 3'd0);
            end else begin
                send_msg_block(64'd0, 1, 3'd0);
            end

            wait(done);

            if (is_enc) begin
                if (tag_out !== exp_tag) begin
                    $display("X ENC FAILED [Count %0d]: Tag mismatch! Expected %h, Got %h", id, exp_tag, tag_out);
                    error_cnt = error_cnt + 1;
                end else begin
                    $display("V ENC PASS [Count %0d]", id);
                end
            end else begin
                if (!auth_pass) begin
                    $display("X DEC FAILED [Count %0d]: Authentication Failed!", id);
                    error_cnt = error_cnt + 1;
                end else begin
                    $display("V DEC PASS [Count %0d]", id);
                end
            end
        end
    endtask

    task get_tv(
        input integer id,
        output reg [31:0] o_ad_len,
        output reg [31:0] o_pt_len,
        output reg [127:0] o_tag,
        output reg [8191:0] o_ad,
        output reg [8191:0] o_pt,
        output reg [8191:0] o_ct
    );
        begin
            o_ad = 0; o_pt = 0; o_ct = 0;
            case(id)
                1: begin o_ad_len=0; o_pt_len=0; o_tag=128'hE355159F292911F794CB1432A0103A8A; end
                2: begin o_ad_len=1; o_pt_len=0; o_ad=8'h00; o_tag=128'h944DF887CD4901614C5DEDBC42FC0DA0; end
                3: begin o_ad_len=2; o_pt_len=0; o_ad=16'h0001; o_tag=128'hCE1936FBDD191058DEA8769B79319858; end
                4: begin o_ad_len=3; o_pt_len=0; o_ad=24'h000102; o_tag=128'h4C9450689BE3D7C23925A4219DE6B50C; end
                5: begin o_ad_len=4; o_pt_len=0; o_ad=32'h00010203; o_tag=128'h082389C8819A82BD98C04A3C64A63AA9; end
                
                50: begin o_ad_len=16; o_pt_len=1; o_ad=128'h000102030405060708090A0B0C0D0E0F; o_pt=8'h00; o_ct=8'h1E; o_tag=128'hE4C30EAE829E2C5569A1D688C2616AEE; end
                51: begin o_ad_len=17; o_pt_len=1; o_ad=136'h000102030405060708090A0B0C0D0E0F10; o_pt=8'h00; o_ct=8'h86; o_tag=128'hD1F8C7161F1D833B98DB88606A9776A7; end
                52: begin o_ad_len=18; o_pt_len=1; o_ad=144'h000102030405060708090A0B0C0D0E0F1011; o_pt=8'h00; o_ct=8'h77; o_tag=128'h4911D56576A4A923553F3DF5EB16C5C7; end
                53: begin o_ad_len=19; o_pt_len=1; o_ad=152'h000102030405060708090A0B0C0D0E0F101112; o_pt=8'h00; o_ct=8'hD3; o_tag=128'hB95AA2A80F63D23F93E2968806AEEE85; end
                54: begin o_ad_len=20; o_pt_len=1; o_ad=160'h000102030405060708090A0B0C0D0E0F10111213; o_pt=8'h00; o_ct=8'hA3; o_tag=128'h7D44820FFE19D8C5ECA1E9D3972F4A27; end
                55: begin o_ad_len=21; o_pt_len=1; o_ad=168'h000102030405060708090A0B0C0D0E0F1011121314; o_pt=8'h00; o_ct=8'h74; o_tag=128'h348C6460F114F835F7A7900C0A5B6E2E; end
                
                490: begin o_ad_len=27; o_pt_len=14; o_ad=216'h000102030405060708090A0B0C0D0E0F101112131415161718191A; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'h31686725B47CA995FC470C8F2619; o_tag=128'h68829D07F56E3F0FBBE5A584393F1C42; end
                491: begin o_ad_len=28; o_pt_len=14; o_ad=224'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'hC780135837218C32D20D3D705A15; o_tag=128'hFF56CD6F98C3239399793633BFA4F741; end
                492: begin o_ad_len=29; o_pt_len=14; o_ad=232'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'h3BD2F45CE90E0F3731641C6EC79E; o_tag=128'hB6876B775211FB5050D2A3C3A7123779; end
                493: begin o_ad_len=30; o_pt_len=14; o_ad=240'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'h270D846F99173380199972D19BE4; o_tag=128'hBCFEF42F569A425BD359A32FA6DD6A84; end
                494: begin o_ad_len=31; o_pt_len=14; o_ad=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'hD670F5A44971BE13F91BDD82E515; o_tag=128'h5335B6656748D1037784327DF981FC3D; end
                495: begin o_ad_len=32; o_pt_len=14; o_ad=256'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F; o_pt=112'h000102030405060708090A0B0C0D; o_ct=112'hB96C78651B6246B0C3B1A5D373B0; o_tag=128'h5E263B3F65163754B40BE6701016F2EF; end
                
                496: begin o_ad_len=0; o_pt_len=15; o_pt=120'h000102030405060708090A0B0C0D0E; o_ct=120'hBC820DBDF7A4631C5B29884AD69175; o_tag=128'h16D420A5BC2E5357D010818F0B5F7859; end
                497: begin o_ad_len=1; o_pt_len=15; o_ad=8'h00; o_pt=120'h000102030405060708090A0B0C0D0E; o_ct=120'hBD4640C4DA2FFA56DC79F7FDD07369; o_tag=128'hA9779D0C974CA41061D4E1250B93D8F0; end
                498: begin o_ad_len=2; o_pt_len=15; o_ad=16'h0001; o_pt=120'h000102030405060708090A0B0C0D0E; o_ct=120'h6E9F820D5468A0D476620F58650864; o_tag=128'hD33F2CFD1B323CADF3356028727A65E6; end
                
                1041: begin o_ad_len=17; o_pt_len=31; o_ad=136'h000102030405060708090A0B0C0D0E0F10; o_pt=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_ct=248'h8684539A9FCFF9F68A7A496010F129B5C9A3860BFF417050D0281D0BA8F4B8; o_tag=128'h17F8CF3FD814F99F92665B6C532638DF; end
                1042: begin o_ad_len=18; o_pt_len=31; o_ad=144'h000102030405060708090A0B0C0D0E0F1011; o_pt=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_ct=248'h77AA511159627C4B855E67F95B3ABF1490F306CD374BC3B6C7BACE95EC2DF1; o_tag=128'hD01B7A5605DD551C7681DC91E0868832; end
                1043: begin o_ad_len=19; o_pt_len=31; o_ad=152'h000102030405060708090A0B0C0D0E0F101112; o_pt=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_ct=248'hD323863E597297EAB51C8F134D3ED02E4EDBA0794BBA65739BDF24038A4A7A; o_tag=128'h659779D7B9A164F05FE3859FD5B9F5B2; end
                1044: begin o_ad_len=20; o_pt_len=31; o_ad=160'h000102030405060708090A0B0C0D0E0F10111213; o_pt=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_ct=248'hA31AC9A1D4D18222F332F245C70AB28D022B47C1D0D3135D34F55168C0CB3B; o_tag=128'h6A51C64E4824A249B047234B98F638A3; end
                1045: begin o_ad_len=21; o_pt_len=31; o_ad=168'h000102030405060708090A0B0C0D0E0F1011121314; o_pt=248'h000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E; o_ct=248'h74EA9BA2635DCBAA400A5C24E4970400CA78DE82412D5B177C5DA6BE3F2D31; o_tag=128'h2C8341E1E9D0C1080342516CD3AEBA63; end
                default: begin o_ad_len=0; o_pt_len=0; o_tag=128'd0; end
            endcase
        end
    endtask

    integer test_ids[0:24];
    integer k;

    initial begin
        test_ids[0]  = 1;    test_ids[1]  = 2;    test_ids[2]  = 3;    test_ids[3]  = 4;    test_ids[4]  = 5;
        test_ids[5]  = 50;   test_ids[6]  = 51;   test_ids[7]  = 52;   test_ids[8]  = 53;   test_ids[9]  = 54;
        test_ids[10] = 55;   test_ids[11] = 490;  test_ids[12] = 491;  test_ids[13] = 492;  test_ids[14] = 493;
        test_ids[15] = 494;  test_ids[16] = 495;  test_ids[17] = 496;  test_ids[18] = 497;  test_ids[19] = 498;
        test_ids[20] = 1041; test_ids[21] = 1042; test_ids[22] = 1043; test_ids[23] = 1044; test_ids[24] = 1045;

        clk = 0; rst_n = 0; start = 0; encrypt = 0;
        ad_valid = 0; ad_last = 0; ad_bytes = 0;
        msg_valid = 0; msg_last = 0; msg_bytes = 0;
        
        key = 128'h000102030405060708090A0B0C0D0E0F;
        nonce = 128'h000102030405060708090A0B0C0D0E0F;

        #100 rst_n = 1;
        #100;

        $display("STARTING MASKED ASCON-128 SYSTEM TEST VECTOR RUN");

        for (k = 0; k < 25; k = k + 1) begin
            $display("\n Running Official Test Vector [Count %0d] ", test_ids[k]);
            run_test(test_ids[k], 1); 
            #200;
            run_test(test_ids[k], 0); 
            #200;
        end
        
        if (error_cnt == 0)
            $display("ALL TESTS PASSED SUCCESSFULLY");
        else
            $display("TEST FINISHED WITH %0d ERRORS", error_cnt);
        $finish;
    end

endmodule