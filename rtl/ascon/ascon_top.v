// Ascon Lightweight Cryptography - Unmasked Hardware Implementation
// Course: ELE414 Final Report
//
// ARCHITECTURE REFERENCES:
//   [8] K. Gaj et al., "Hardware API for Lightweight Cryptography,"
//       GMU CERG, 2020. https://github.com/GMUCERG/LWC
//       -> Top-level FSM phase partitioning and handshake protocol
//          are derived from the LWC Hardware API specification.
//
//   [6] C. Dobraunig et al., "Ascon v1.2: Lightweight Cryptography
//       for the Internet of Things," NIST LWC Finalist, 2021.
//       https://ascon.iaik.tugraz.at/
//       -> All mathematical operations (S-box, linear layer, round
//          constants) strictly follow the official Ascon v1.2 spec.
//
// NOTE: This is an independent educational implementation.
//       No source code was copied from either reference repository.

`timescale 1ns / 1ps

module ascon_top (
    input wire clk,
    input wire rst_n,
    
    input wire start,
    input wire encrypt,      
    input wire [127:0] key,
    input wire [127:0] nonce,
    
    input wire [63:0] ad_data,
    input wire ad_valid,
    input wire ad_last,
    
    input wire [63:0] msg_data,
    input wire msg_valid,
    input wire msg_last,
    input wire [2:0] msg_bytes, 
    input wire [127:0] tag_in,  
    
    output reg [63:0] out_data,
    output reg out_valid,
    output reg out_last,
    output reg [127:0] tag_out,
    output reg auth_pass,
    
    output reg busy,
    output reg done
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

    reg [3:0] state;
    reg [3:0] next_state;

    reg [63:0] x0, x1, x2, x3, x4;
    reg [63:0] K1, K2;
    reg is_encrypt;
    reg ad_processed;      
    reg ad_finish_pending; 

    reg perm_start;
    reg [3:0] perm_rounds;
    wire [319:0] perm_state_in = {x0, x1, x2, x3, x4};
    wire [319:0] perm_state_out;
    wire perm_done;
    wire perm_busy; 

    ascon_permutation u_perm (
        .clk(clk),
        .rst_n(rst_n),
        .start(perm_start),
        .rounds(perm_rounds),
        .state_in(perm_state_in),
        .state_out(perm_state_out),
        .done(perm_done),
        .busy(perm_busy)
    );
    
    reg [63:0] valid_mask;
    always @(*) begin
        case(msg_bytes)
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

    wire [63:0] pt_dec_last = (x0 ^ msg_data) & valid_mask;
    
    wire [63:0] pad_din = (state == PR_MES && msg_last) ? 
                          (is_encrypt ? msg_data : pt_dec_last) : ad_data;
    
    reg [63:0] pad_bit;
    always @(*) begin
        case (msg_bytes)
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
    
// FSM Phase Partitioning & Handshake Protocol
// Reference: [8] GMU LWC Hardware API, Section 3-4
// The state encoding, idle/compute/done handshaking, and tag-length
// signaling convention follow the LWC compliant interface design.

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
                if (!perm_start && !perm_busy && msg_valid && msg_last) begin
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

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            x0 <= 64'd0; x1 <= 64'd0; x2 <= 64'd0; x3 <= 64'd0; x4 <= 64'd0;
            K1 <= 64'd0; K2 <= 64'd0;
            is_encrypt <= 1'b0;
            ad_processed <= 1'b0;
            ad_finish_pending <= 1'b0;
            perm_start <= 1'b0;
            perm_rounds <= 4'd12;
            out_valid <= 1'b0;
            out_last <= 1'b0;
            out_data <= 64'd0;
            tag_out <= 128'd0;
            auth_pass <= 1'b0;
            busy <= 1'b0;
            done <= 1'b0;
        end else begin
           
            state <= next_state;
            
            out_valid <= 1'b0;
            out_last <= 1'b0;
            perm_start <= 1'b0;
            done <= 1'b0;

            case (state)
                IDLE: begin
                    if (start) begin
                        is_encrypt <= encrypt;
                        K1 <= key[127:64];
                        K2 <= key[63:0];
                        x3 <= nonce[127:64];
                        x4 <= nonce[63:0];
                        busy <= 1'b1;
                    end else begin
                        busy <= 1'b0;
                    end
                end

                INI_LD: begin
                    x0 <= 64'h80400c0600000000;
                    x1 <= K1; x2 <= K2;
                end

                INI_PER: begin
                    if (!perm_start && !perm_done && !perm_busy) begin
                        perm_start <= 1'b1;
                        perm_rounds <= 4'd12;
                    end else if (perm_done) begin
                        {x0, x1, x2, x3, x4} <= perm_state_out;
                    end
                end

                INI_KEY: begin
                    x3 <= x3 ^ K1;
                    x4 <= x4 ^ K2;
                    ad_processed <= 1'b0;
                end

                PR_AD: begin
                    if (perm_done) begin
                        {x0, x1, x2, x3, x4} <= perm_state_out;
                        if (ad_finish_pending) ad_finish_pending <= 1'b0;
                    end else if (!perm_start && !perm_busy && ad_valid) begin 
                        ad_processed <= 1'b1;
                        perm_start <= 1'b1;
                        perm_rounds <= 4'd6;
                        x0 <= x0 ^ (!ad_last ? ad_data : pad_out);
                        if (ad_last) ad_finish_pending <= 1'b1;
                    end
                end

                AD_DM: begin
                    x4 <= x4 ^ 64'd1;
                end

                PR_MES: begin
                    if (perm_done) begin
                        {x0, x1, x2, x3, x4} <= perm_state_out;
                    end else if (!perm_start && !perm_busy && msg_valid) begin 
                        out_valid <= 1'b1;
                        if (!msg_last) begin 
                            perm_start <= 1'b1;
                            perm_rounds <= 4'd6;
                            out_data <= x0 ^ msg_data;
                            x0 <= is_encrypt ? (x0 ^ msg_data) : msg_data;
                        end else begin 
                            out_last <= 1'b1;
                            out_data <= is_encrypt ? ((x0 ^ msg_data) & valid_mask) : pt_dec_last;
                            x0 <= x0 ^ pad_out;
                        end
                    end
                end

                FIN_KEY1: begin
                    x1 <= x1 ^ K1;
                    x2 <= x2 ^ K2;
                end

                FIN_PER: begin
                    if (!perm_start && !perm_done && !perm_busy) begin
                        perm_start <= 1'b1;
                        perm_rounds <= 4'd12;
                    end else if (perm_done) begin
                        {x0, x1, x2, x3, x4} <= perm_state_out;
                    end
                end

                FIN_KEY2: begin
                    x3 <= x3 ^ K1;
                    x4 <= x4 ^ K2;
                end

                DONE: begin
                    tag_out <= {x3, x4};
                    if (!is_encrypt) begin
                        auth_pass <= ({x3, x4} == tag_in);
                    end
                    done <= 1'b1;
                    busy <= 1'b0; 
                end
                
                default: ; 
            endcase
        end
    end
endmodule
