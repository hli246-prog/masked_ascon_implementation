// Masked Ascon 
// Course: ELE414 Final Report
//
// MASKING SCHEME REFERENCES:
//   [2] H. Groß, S. Mangard, and T. Korak, "Domain-Oriented Masking:
//       Compact Masked Hardware Implementations with Arbitrary Protection
//       Order," IACR ePrint 2016/486, 2016. https://eprint.iacr.org/2016/486
//       -> Core masking framework: domain separation, register placement,
//          and glitch-resistant composition rules for hardware.
//
//   [11] Y. Ishai, A. Sahai, and D. Wagner, "Private Circuits: Securing
//        Hardware against Probing Attacks," CRYPTO 2003, vol. 2729,
//        pp. 463–481.
//        -> Theoretical foundation: ISW masked AND gadget used as the
//           nonlinear layer primitive in this implementation.
//
//   [12] "simpleserial-ascon: Masked Ascon Software Implementations,"
//        GitHub. https://github.com/ascon/simpleserial-ascon
//        -> Share splitting strategy and linear-layer isolation approach
//           were informed by this reference software implementation.
//
// NOTE: This is an independent educational hardware implementation.
//       No HDL code was copied from any reference repository.
//       The design follows the above publications' methodologies.

`timescale 1ns / 1ps

module ascon_top_masked (
    input wire clk,
    input wire rst_n,
    
    input wire start,
    input wire encrypt,      
    input wire [127:0] key,
    input wire [127:0] nonce,
    
    input wire [63:0] ad_data,
    input wire ad_valid,
    input wire ad_last,
    input wire [2:0]  ad_bytes, 
    
    input wire [63:0] msg_data,
    input wire msg_valid,
    input wire msg_last,
    input wire [2:0]  msg_bytes, 
    input wire [127:0] tag_in,  
    
    output reg [63:0] out_data,
    output reg out_valid,
    output reg out_last,
    output reg [127:0] tag_out,
    output reg auth_pass,
    
    output reg busy,
    output reg done,

    input wire [319:0] perm_rand_mask, 
    input wire [63:0]  rand_key1,      
    input wire [63:0]  rand_key2,      
    input wire [63:0]  rand_dec,

    input wire [63:0]  rand_dec_last 
);

    localparam IDLE       = 4'd0;
    localparam INI_LD     = 4'd1;
    localparam INI_PER    = 4'd2;
    localparam INI_KEY    = 4'd3;
    localparam PR_AD      = 4'd4;
    localparam AD_DM      = 4'd5;
    localparam PR_MES     = 4'd6;
    localparam FIN_KEY1   = 4'd7;
    localparam FIN_PER    = 4'd8;
    localparam FIN_KEY2   = 4'd9;
    localparam DONE       = 4'd10;

    reg [3:0] state, next_state;


    reg [63:0] x0_s0, x1_s0, x2_s0, x3_s0, x4_s0;
    reg [63:0] x0_s1, x1_s1, x2_s1, x3_s1, x4_s1;
    reg [63:0] K1_s0, K1_s1, K2_s0, K2_s1;
    
    reg is_encrypt;
    reg ad_processed;      
    reg ad_finish_pending; 

    reg perm_start;
    reg [3:0] perm_rounds;
    
    wire [319:0] perm_state_in_s0 = {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0};
    wire [319:0] perm_state_in_s1 = {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1};
    wire [319:0] perm_state_out_s0, perm_state_out_s1;
    wire perm_done, perm_busy; 

    ascon_permutation_masked u_perm_masked (
        .clk(clk),
        .rst_n(rst_n),
        .start(perm_start),
        .rounds(perm_rounds),
        .state_in_s0(perm_state_in_s0),
        .state_in_s1(perm_state_in_s1),
        .rand_mask(perm_rand_mask),
        .state_out_s0(perm_state_out_s0),
        .state_out_s1(perm_state_out_s1),
        .done(perm_done),
        .busy(perm_busy)
    );
    
    wire [2:0] active_bytes = (state == PR_AD) ? ad_bytes : msg_bytes;
    reg [63:0] valid_mask;
    always @(*) begin
        case(active_bytes)
            3'd1: valid_mask = 64'hFF00_0000_0000_0000;
            3'd2: valid_mask = 64'hFFFF_0000_0000_0000;
            3'd3: valid_mask = 64'hFFFF_FF00_0000_0000;
            3'd4: valid_mask = 64'hFFFF_FFFF_0000_0000;
            3'd5: valid_mask = 64'hFFFF_FFFF_FF00_0000;
            3'd6: valid_mask = 64'hFFFF_FFFF_FFFF_0000;
            3'd7: valid_mask = 64'hFFFF_FFFF_FFFF_FF00;
            default: valid_mask = 64'h0000_0000_0000_0000; 
        endcase
    end

    wire [63:0] pt_dec_last = (x0_s0 ^ x0_s1 ^ msg_data) & valid_mask;
    
    wire [63:0] pad_din = (state == PR_MES && msg_last) ? 
                          (is_encrypt ? msg_data : pt_dec_last) : ad_data;
    
    reg [63:0] pad_bit;
    always @(*) begin
        case (active_bytes)
            3'd0: pad_bit = 64'h8000_0000_0000_0000;
            3'd1: pad_bit = 64'h0080_0000_0000_0000;
            3'd2: pad_bit = 64'h0000_8000_0000_0000;
            3'd3: pad_bit = 64'h0000_0080_0000_0000;
            3'd4: pad_bit = 64'h0000_0000_8000_0000;
            3'd5: pad_bit = 64'h0000_0000_0080_0000; 
            3'd6: pad_bit = 64'h0000_0000_0000_8000;
            3'd7: pad_bit = 64'h0000_0000_0000_0080;
            default: pad_bit = 64'h0000_0000_0000_0000;
        endcase
    end
    
    wire [63:0] pad_out = (pad_din & valid_mask) | pad_bit;

    always @(*) begin
        next_state = state; 
        case (state)
            IDLE:     if (start) next_state = INI_LD;
            INI_LD:   next_state = INI_PER;
            INI_PER:  if (perm_done) next_state = INI_KEY;
            INI_KEY:  next_state = PR_AD;
            PR_AD: begin
                if (perm_done && ad_finish_pending) begin
                    next_state = AD_DM;
                end else if (!perm_start && !perm_busy && !ad_valid && msg_valid && !ad_processed) begin
                    next_state = AD_DM;
                end
            end
            AD_DM:    next_state = PR_MES;
            
            PR_MES: begin
                if (out_last) begin
                    next_state = FIN_KEY1;
                end
            end
            
            FIN_KEY1: next_state = FIN_PER;
            FIN_PER:  if (perm_done) next_state = FIN_KEY2;
            FIN_KEY2: next_state = DONE;
            DONE:     next_state = IDLE;
            default:  next_state = IDLE;
        endcase
    end

    reg perm_trig_lock; 

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            x0_s0 <= 0; x1_s0 <= 0; x2_s0 <= 0; x3_s0 <= 0; x4_s0 <= 0;
            x0_s1 <= 0; x1_s1 <= 0; x2_s1 <= 0; x3_s1 <= 0; x4_s1 <= 0;
            K1_s0 <= 0; K1_s1 <= 0; K2_s0 <= 0; K2_s1 <= 0;
            is_encrypt <= 0; ad_processed <= 0; ad_finish_pending <= 0;
            perm_start <= 0; perm_rounds <= 12; perm_trig_lock <= 0;
            out_valid <= 0; out_last <= 0; out_data <= 0; tag_out <= 0;
            auth_pass <= 0; busy <= 0; done <= 0;
        end else begin
            state <= next_state;
            out_valid <= 1'b0; out_last <= 1'b0; perm_start <= 1'b0; done <= 1'b0;
            
            if (perm_done) perm_trig_lock <= 1'b0; 

            case (state)
                IDLE: begin
                    if (start) begin
                        is_encrypt <= encrypt;
                        K1_s0 <= rand_key1;             K1_s1 <= key[127:64] ^ rand_key1;
                        K2_s0 <= rand_key2;             K2_s1 <= key[63:0]   ^ rand_key2;
                        x3_s0 <= 64'd0;                 x3_s1 <= nonce[127:64];
                        x4_s0 <= 64'd0;                 x4_s1 <= nonce[63:0];
                        busy <= 1'b1;
                    end else busy <= 1'b0;
                end

                INI_LD: begin
                    x0_s0 <= 64'd0; x0_s1 <= 64'h80400c0600000000;
                    x1_s0 <= K1_s0; x1_s1 <= K1_s1; 
                    x2_s0 <= K2_s0; x2_s1 <= K2_s1;
                end

                INI_PER: begin
                    if (!perm_start && !perm_done && !perm_busy && !perm_trig_lock) begin
                        perm_start <= 1'b1; perm_rounds <= 4'd12; perm_trig_lock <= 1'b1;
                    end else if (perm_done) begin
                        {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0} <= perm_state_out_s0;
                        {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1} <= perm_state_out_s1;
                    end
                end

                INI_KEY: begin
                    x3_s0 <= x3_s0 ^ K1_s0; x3_s1 <= x3_s1 ^ K1_s1;
                    x4_s0 <= x4_s0 ^ K2_s0; x4_s1 <= x4_s1 ^ K2_s1;
                    ad_processed <= 1'b0;
                end

                PR_AD: begin
                    if (perm_done) begin
                        {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0} <= perm_state_out_s0;
                        {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1} <= perm_state_out_s1;
                        if (ad_finish_pending) ad_finish_pending <= 1'b0;
                    end else if (!perm_start && !perm_busy && ad_valid && !perm_trig_lock) begin
                        ad_processed <= 1'b1; perm_start <= 1'b1; perm_rounds <= 4'd6; perm_trig_lock <= 1'b1;
                        x0_s1 <= x0_s1 ^ (!ad_last ? ad_data : pad_out);
                        if (ad_last) ad_finish_pending <= 1'b1;
                    end
                end

                AD_DM: begin
                    x4_s1 <= x4_s1 ^ 64'd1;
                end

                PR_MES: begin
                    if (perm_done) begin
                        {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0} <= perm_state_out_s0;
                        {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1} <= perm_state_out_s1;
                    end else if (!perm_start && !perm_busy && msg_valid && !perm_trig_lock) begin
                        out_valid <= 1'b1;
                        if (!msg_last) begin
                            perm_start <= 1'b1; perm_rounds <= 4'd6; perm_trig_lock <= 1'b1;
                            out_data <= x0_s0 ^ x0_s1 ^ msg_data;
                            if (is_encrypt) begin
                                x0_s1 <= x0_s1 ^ msg_data;
                            end else begin
                                x0_s0 <= rand_dec;
                                x0_s1 <= msg_data ^ rand_dec;
                            end
                        end else begin
                            out_last <= 1'b1;
                            if (is_encrypt) begin
                                out_data <= (x0_s0 ^ x0_s1 ^ msg_data) & valid_mask;
                                x0_s1 <= x0_s1 ^ pad_out;
                            end else begin
                                out_data <= pt_dec_last;
                                
                                x0_s0 <= (rand_dec_last & valid_mask) | (x0_s0 & ~valid_mask);
                                x0_s1 <= ((msg_data ^ rand_dec_last) & valid_mask) | (x0_s1 & ~valid_mask) ^ pad_bit;
                            end
                        end
                    end
                end

                FIN_KEY1: begin
                    x1_s0 <= x1_s0 ^ K1_s0; x1_s1 <= x1_s1 ^ K1_s1;
                    x2_s0 <= x2_s0 ^ K2_s0; x2_s1 <= x2_s1 ^ K2_s1;
                end

                FIN_PER: begin
                    if (!perm_start && !perm_done && !perm_busy && !perm_trig_lock) begin
                        perm_start <= 1'b1; perm_rounds <= 4'd12; perm_trig_lock <= 1'b1;
                    end else if (perm_done) begin
                        {x0_s0, x1_s0, x2_s0, x3_s0, x4_s0} <= perm_state_out_s0;
                        {x0_s1, x1_s1, x2_s1, x3_s1, x4_s1} <= perm_state_out_s1;
                    end
                end

                FIN_KEY2: begin
                    x3_s0 <= x3_s0 ^ K1_s0; x3_s1 <= x3_s1 ^ K1_s1;
                    x4_s0 <= x4_s0 ^ K2_s0; x4_s1 <= x4_s1 ^ K2_s1;
                end

                DONE: begin
                    tag_out <= {x3_s0 ^ x3_s1, x4_s0 ^ x4_s1};
                    if (!is_encrypt) begin
                        auth_pass <= ({x3_s0 ^ x3_s1, x4_s0 ^ x4_s1} == tag_in);
                    end
                    done <= 1'b1; busy <= 1'b0;
                end
            endcase
        end
    end
endmodule
