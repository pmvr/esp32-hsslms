#include "hss.h"

void log_buffer(const uint8_t *buffer, const int n) {
  char s[3];
  char hex[] = "0123456789ABCDEF";

  s[2] = 0;
  for (int i = 0; i < n; i++) {
    s[0] = hex[buffer[i] >> 4];
    s[1] = hex[buffer[i] & 0x0f];
    Serial.print(s);
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  Serial.println("Starting ...");

  unsigned long start = millis();
  HSS_Priv sk = HSS_Priv(std::vector<LMS_ALGORITHM_TYPE> {LMS_SHA256_M32_H5}, LMOTS_SHA256_N32_W2);
  double duration = (millis() - start) / 1000.0;
  Serial.print("Key-Gen: "); Serial.println(duration, 3);

  start = millis();
  std::string signature = sk.sign("abc");
  duration = (millis() - start) / 1000.0;
  Serial.print("Sig-Gen: "); Serial.println(duration, 3);
  //log_buffer((uint8_t *)signature.c_str(), signature.size());

  start = millis();
  HSS_Pub vk = sk.gen_pub();
  duration = (millis() - start) / 1000.0;
  Serial.print("Pub-Gen: "); Serial.println(duration, 3);
  try {
    start = millis();
    vk.verify("abc", signature);
    duration = (millis() - start) / 1000.0;
    Serial.print("Verify: "); Serial.println(duration, 3);
    Serial.println("Vaild (-:");
  }
  catch (INVALID &e) {
    Serial.println("Invaild )-:");
    Serial.println(e.what());
  }

  // rfc 8551 test case 1
  Serial.println("Performing test case 1 defined in RFC 8551");
  vk = HSS_Pub(std::string("\000\000\000\002\000\000\000\005\000\000\000\004\141\245\325\175\067\365\344\153\373\165\040\200\153\007\241\270\120\145\016\073\061\376\112\167\076\242\232\007\360\234\362\352\060\345\171\360\337\130\357\216\051\215\240\103\114\262\270\170", 60));
  std::string message = "The powers not delegated to the United States by the Constitution, nor prohibited by it to the States, are reserved to the States respectively, or to the people.\n";
  signature = std::string("\000\000\000\001\000\000\000\005\000\000\000\004\323\053\126\147\035\176\271\210\063\304\233\103\074\047\045\206\274\112\034\212\211\160\122\217\372\004\271\146\371\102\156\271\226\132\045\277\323\177\031\153\220\163\363\324\242\062\376\266\221\050\354\105\024\157\206\051\057\235\377\226\020\247\277\225\246\114\177\140\366\046\032\142\004\077\206\307\003\044\267\160\177\133\112\212\156\031\301\024\307\276\206\155\110\207\170\240\340\137\325\306\120\232\156\141\325\131\317\032\167\251\160\336\222\175\140\307\015\075\343\032\177\240\020\011\224\341\142\242\130\056\217\361\261\014\331\235\116\216\101\076\364\151\125\237\175\176\321\054\203\203\102\371\271\311\153\203\244\224\075\026\201\330\113\025\065\177\364\214\245\171\361\237\136\161\361\204\146\362\273\357\113\366\140\302\121\216\262\015\342\366\156\073\024\170\102\151\327\330\166\365\323\135\077\277\307\003\232\106\054\161\153\271\366\211\032\177\101\255\023\076\236\037\155\225\140\271\140\347\167\174\122\360\140\111\057\055\174\146\016\024\161\340\176\162\145\125\142\003\132\274\232\160\033\107\076\313\303\224\074\153\234\117\044\005\243\313\213\370\246\221\312\121\323\366\255\057\102\213\253\157\072\060\365\135\331\142\125\143\360\247\136\343\220\343\205\343\256\013\220\151\141\354\364\032\340\163\240\131\014\056\266\040\117\104\203\034\046\335\166\214\065\261\147\262\214\350\334\230\212\067\110\045\122\060\316\371\236\277\024\347\060\143\057\047\101\104\211\200\212\372\261\321\347\203\355\004\121\155\340\022\111\206\202\041\053\007\201\005\171\262\120\066\131\101\274\311\201\102\332\023\140\236\227\150\252\366\135\347\142\015\253\354\051\353\202\241\177\336\065\257\025\255\043\214\163\370\033\333\215\354\057\300\347\371\062\160\020\231\166\053\067\364\074\112\074\040\001\012\075\162\342\366\006\276\020\215\061\016\143\237\011\316\162\206\200\015\236\370\241\244\002\201\314\132\176\251\215\052\334\174\164\000\302\376\132\020\025\122\337\116\074\314\375\014\277\055\337\135\306\167\234\273\306\217\356\014\076\376\116\302\053\203\242\312\243\344\216\010\011\240\247\120\267\074\315\317\074\171\346\130\014\025\117\212\130\367\362\103\065\356\305\305\353\136\014\360\035\317\104\071\102\100\225\374\353\007\177\146\336\325\276\307\073\047\305\271\366\112\052\232\362\360\174\005\351\236\134\370\017\000\045\056\071\333\062\366\301\226\164\361\220\311\373\305\006\330\046\205\167\023\257\322\312\153\270\134\330\301\007\064\165\122\363\005\165\245\101\170\026\253\115\263\366\003\362\337\126\373\304\023\347\320\254\330\275\330\023\122\262\107\037\301\274\117\036\362\226\376\241\042\004\003\106\153\032\376\170\271\117\176\317\174\306\057\271\053\341\117\030\302\031\043\204\353\316\257\210\001\257\337\224\177\151\214\351\306\316\266\226\355\160\351\350\173\001\104\101\176\215\173\257\045\353\137\160\360\237\001\157\311\045\264\333\004\212\270\330\313\052\146\034\343\265\172\332\147\127\037\135\325\106\374\042\313\037\227\340\353\321\246\131\046\261\043\117\320\117\027\034\364\151\307\153\210\114\363\021\134\316\157\171\054\310\116\066\332\130\226\014\137\035\166\017\062\301\057\256\364\167\351\114\222\353\165\142\133\152\067\036\374\162\326\014\245\351\010\263\247\335\151\376\360\044\221\120\343\356\275\376\323\234\275\303\316\227\004\210\052\040\162\307\136\023\122\173\172\130\032\125\141\150\170\075\301\351\165\105\343\030\145\335\304\153\074\225\170\065\332\045\053\267\062\215\076\342\006\044\105\337\270\136\370\303\137\216\037\063\161\257\064\002\074\357\142\156\012\361\340\274\001\163\121\252\342\253\217\134\141\056\255\013\162\232\035\005\235\002\277\341\216\372\227\033\163\000\350\202\066\012\223\260\045\377\227\351\340\356\300\363\363\361\060\071\241\177\210\260\317\200\217\110\204\061\140\154\261\077\222\101\364\017\104\345\067\323\002\306\112\117\037\112\271\111\271\376\357\255\313\161\253\120\357\047\326\326\312\205\020\361\120\310\137\265\045\277\045\160\075\367\040\233\140\146\360\234\067\050\015\131\022\215\057\017\143\174\175\175\177\255\116\321\301\352\004\346\050\322\041\343\330\333\167\267\310\170\311\101\034\257\305\007\032\064\240\017\114\360\167\070\221\047\123\337\316\110\360\165\166\360\324\371\117\102\306\327\157\174\351\163\351\066\160\225\272\176\232\066\111\267\364\141\331\371\254\023\062\244\321\004\114\226\256\376\346\166\166\100\033\144\105\174\124\326\137\357\145\000\305\234\337\266\232\367\266\335\337\313\017\010\142\170\335\212\320\150\140\170\337\260\363\367\234\330\223\323\024\026\206\110\111\230\230\373\300\316\325\371\133\164\350\377\024\327\065\315\352\226\213\356\164\000\000\000\005\330\270\021\057\222\000\245\345\014\112\046\041\145\275\064\054\330\000\270\111\150\020\274\161\142\167\103\132\303\166\162\215\022\232\306\355\250\071\246\363\127\265\240\103\207\305\316\227\070\052\170\362\244\067\051\027\356\374\277\223\366\073\265\221\022\365\333\344\000\275\111\344\120\036\205\237\210\133\360\163\156\220\245\011\263\012\046\277\254\214\027\265\231\034\025\176\265\227\021\025\252\071\357\330\325\144\246\271\002\202\303\026\212\362\323\016\370\235\121\277\024\145\105\020\241\053\212\024\114\312\030\110\317\175\245\234\302\263\331\320\151\055\322\242\013\243\206\064\200\342\133\033\205\356\206\014\142\277\121\066\000\000\000\005\000\000\000\004\322\361\117\366\064\152\371\144\126\237\175\154\270\200\241\266\154\120\004\221\175\246\352\376\115\236\366\306\100\173\075\260\345\110\133\022\055\236\276\025\315\251\074\376\305\202\327\253\000\000\000\012\000\000\000\004\007\003\304\221\347\125\213\065\001\036\316\065\222\352\245\332\115\221\207\206\167\022\063\350\065\073\304\366\043\043\030\134\225\312\340\133\211\236\065\337\375\161\160\124\160\142\011\230\216\277\337\156\067\226\013\265\303\215\166\127\350\277\376\357\233\300\102\332\113\105\045\145\004\205\306\155\014\341\233\061\165\207\306\272\113\377\314\102\216\045\320\211\061\347\055\373\152\022\014\126\022\064\102\130\270\136\375\267\333\035\271\341\206\132\163\312\371\145\127\353\071\355\076\077\102\151\063\254\236\355\333\003\241\322\067\112\367\277\167\030\125\167\105\142\067\371\336\055\140\021\074\043\370\106\337\046\372\224\040\010\246\230\231\114\010\047\331\016\206\324\076\015\367\364\277\315\260\233\206\243\163\271\202\210\267\011\112\330\032\001\205\254\020\016\117\054\137\303\214\000\074\032\266\376\244\171\353\057\136\276\110\365\204\327\025\233\212\332\003\130\156\145\255\234\226\237\152\354\277\344\114\363\126\210\212\173\025\243\377\007\117\167\027\140\262\157\234\004\210\116\341\372\243\051\373\364\346\032\362\072\356\177\245\324\331\245\337\317\103\304\302\154\350\256\242\316\212\051\220\327\272\173\127\020\213\107\332\277\276\255\262\262\133\074\254\301\254\014\357\064\154\273\220\373\004\113\356\344\372\302\140\072\104\053\337\176\120\162\103\267\061\234\231\104\261\130\156\211\235\103\034\177\221\274\314\310\151\015\277\131\262\203\206\262\061\137\075\066\357\056\252\074\363\013\053\121\364\213\161\260\003\337\260\202\111\110\102\001\004\077\145\365\243\357\153\275\141\335\376\350\032\312\234\346\000\201\046\052\000\000\004\200\334\274\232\075\246\373\357\134\034\012\125\344\212\016\162\237\221\204\374\261\100\174\061\122\235\262\150\366\376\120\003\052\066\074\230\001\060\150\067\372\372\275\371\127\375\227\352\374\200\333\321\145\344\065\320\342\337\330\066\242\213\065\100\043\222\113\157\267\344\213\300\263\355\225\356\246\114\055\100\057\115\163\114\215\302\157\072\305\221\202\135\256\360\036\256\074\070\343\062\215\000\247\175\306\127\003\117\050\174\313\017\016\034\232\174\275\310\050\366\047\040\136\107\067\270\113\130\067\145\121\324\114\022\303\302\025\310\022\240\227\007\211\310\075\345\035\152\327\207\047\031\143\062\177\012\137\273\153\131\007\336\300\054\232\220\223\112\365\241\306\073\162\310\046\123\140\135\035\314\345\025\226\263\302\264\126\226\150\237\056\263\202\000\164\227\125\166\222\312\254\115\127\265\336\237\125\151\274\052\320\023\177\324\177\264\176\146\117\313\155\264\227\037\133\076\007\254\355\251\254\023\016\237\070\030\055\351\224\317\361\222\354\016\202\375\155\114\267\363\376\000\201\045\211\267\247\316\121\124\100\105\144\063\001\153\204\245\233\354\146\031\241\306\300\263\175\321\105\016\324\362\330\265\204\101\014\355\250\002\137\135\055\215\320\322\027\157\301\317\054\300\157\250\310\053\355\115\224\116\161\063\236\316\170\017\320\045\275\101\354\064\353\377\235\102\160\243\042\116\001\237\313\104\104\164\324\202\375\055\276\165\357\262\003\211\314\020\315\140\012\273\124\304\176\336\223\340\214\021\116\333\004\021\175\161\115\301\325\045\341\033\355\207\126\031\057\222\235\025\106\053\223\237\363\365\057\042\122\332\056\326\115\217\256\210\201\213\036\372\054\173\010\310\171\117\261\262\024\252\043\075\263\026\050\063\024\036\244\070\077\032\157\022\013\341\333\202\316\066\060\263\102\221\024\106\061\127\246\116\221\043\115\107\136\057\171\313\360\136\115\266\251\100\175\162\306\277\367\321\031\213\134\115\152\255\050\061\333\141\047\111\223\161\132\001\202\307\334\200\211\343\054\205\061\336\355\117\164\061\300\174\002\031\136\272\056\371\036\373\126\023\303\172\367\256\014\006\153\253\306\223\151\160\016\035\322\156\335\300\322\026\307\201\325\156\114\344\176\063\003\372\163\000\177\367\271\111\357\043\276\052\244\333\362\122\006\376\105\302\015\330\210\071\133\045\046\071\032\162\111\226\244\101\126\276\254\200\202\022\205\207\222\277\216\164\313\244\235\356\136\210\022\340\031\332\207\105\113\377\236\204\176\330\075\260\172\363\023\164\060\202\370\200\242\170\366\202\302\275\012\326\210\174\265\237\145\056\025\131\207\326\033\277\152\210\323\156\351\073\140\162\346\145\155\234\313\252\343\326\125\205\056\070\336\263\242\334\370\005\215\311\373\157\052\263\323\263\123\236\267\173\044\212\146\020\221\320\136\266\342\362\227\167\117\346\005\065\230\105\174\306\031\010\061\215\344\270\046\360\374\206\324\273\021\175\063\350\145\252\200\120\011\314\051\030\331\302\370\100\304\332\103\247\003\255\237\133\130\006\026\075\161\141\151\153\132\012\334\000\000\000\005\325\300\321\276\273\006\004\216\326\376\056\362\306\316\363\005\263\355\143\071\101\353\310\263\276\311\163\207\124\315\335\140\341\222\012\332\122\364\075\005\133\120\061\316\346\031\045\040\326\245\021\125\024\205\034\347\375\104\215\112\071\372\342\253\043\065\265\045\364\204\351\264\015\152\112\226\223\224\204\073\334\366\321\114\110\350\001\136\010\253\222\146\054\005\306\351\371\013\145\247\246\040\026\211\231\237\062\277\323\150\345\343\354\234\267\012\307\270\071\220\003\361\165\304\010\205\010\032\011\253\060\064\221\037\341\045\143\020\121\337\004\010\263\224\153\013\336\171\011\021\350\227\213\240\175\325\154\163\347\356", 2644);
  try {
    vk.verify(message, signature);
    Serial.println("Vaild (-:");
  }
  catch (INVALID &e) {
    Serial.println("Invaild )-:");
    Serial.println(e.what());
  }
  // rfc 8551 test case 2
  Serial.println("Performing test case 2 defined in RFC 8551");
  vk = HSS_Pub(std::string("\000\000\000\002\000\000\000\006\000\000\000\003\320\217\253\324\242\011\037\360\250\313\116\330\064\347\105\064\062\245\210\205\315\233\240\103\022\065\106\153\377\226\121\306\311\041\044\100\115\105\372\123\317\026\034\050\361\255\132\216", 60));
  message = "The enumeration in the Constitution, of certain rights, shall not be construed to deny or disparage others retained by the people.\n";
  signature = std::string("\000\000\000\001\000\000\000\003\000\000\000\003\075\106\276\350\146\017\217\041\135\077\226\100\212\172\144\317\034\115\240\053\143\245\137\142\306\146\357\127\007\251\024\316\006\164\350\313\172\125\360\304\215\110\117\061\363\252\112\371\161\232\164\362\054\370\043\271\104\061\320\034\222\156\052\166\273\161\042\155\047\227\000\354\201\311\351\137\261\032\015\020\320\145\047\232\127\226\342\145\256\027\163\174\104\353\214\131\105\010\341\046\251\247\207\013\364\066\010\040\275\353\232\001\331\151\067\171\344\026\202\216\165\275\335\175\214\160\325\012\012\310\272\071\201\011\011\324\105\364\114\265\273\130\336\163\176\140\313\103\105\060\047\206\357\054\153\024\257\041\054\241\236\336\252\073\374\376\213\252\146\041\316\210\110\015\362\067\035\323\172\335\163\054\235\344\352\054\340\337\372\123\311\046\111\241\215\071\245\007\210\364\145\051\207\362\046\241\324\201\150\040\135\366\256\174\130\340\111\242\135\111\007\355\301\252\220\332\212\245\345\367\147\027\163\351\101\330\005\123\140\041\134\153\140\335\065\106\074\362\044\012\234\006\326\224\351\313\124\347\261\341\277\111\115\015\032\050\300\323\032\314\165\026\037\117\110\135\375\074\271\127\216\203\156\302\334\162\057\067\355\060\207\056\007\362\270\275\003\164\353\127\322\054\141\116\011\025\017\154\015\207\164\243\232\156\026\202\021\003\135\305\051\210\253\106\352\312\236\305\227\373\030\264\223\156\146\357\057\015\362\156\215\036\064\332\050\313\263\257\165\043\023\162\014\173\064\124\064\367\055\145\061\103\050\273\260\060\320\360\366\325\344\173\050\352\221\000\217\261\033\005\001\167\005\250\276\073\052\333\203\306\012\124\371\321\321\262\364\166\371\343\223\353\126\225\040\075\053\246\255\201\136\152\021\036\242\223\334\302\020\063\371\105\075\111\310\345\246\070\177\130\213\036\244\367\006\041\174\025\036\005\365\132\156\267\231\173\340\235\126\243\046\243\057\234\272\037\276\034\007\273\111\372\004\316\317\235\361\241\270\025\110\074\165\327\242\174\310\212\321\261\043\216\136\251\206\265\076\010\160\105\162\074\341\141\207\355\242\056\063\262\307\007\011\345\062\121\002\132\275\350\223\226\105\374\214\006\223\351\167\143\222\217\000\262\343\307\132\363\224\055\215\332\356\201\265\232\157\037\147\357\332\016\370\035\021\207\073\131\023\177\147\200\013\065\350\033\001\126\075\030\174\112\025\165\241\254\271\055\010\173\121\172\210\063\070\077\005\323\127\357\106\170\336\014\127\377\237\033\055\246\035\375\345\330\203\030\274\335\344\331\006\034\307\134\055\343\315\107\100\335\167\071\312\076\366\157\031\060\002\157\107\331\353\252\161\073\007\027\157\166\371\123\341\302\347\370\362\161\246\312\067\135\277\270\075\161\233\026\065\247\330\241\070\221\225\171\104\261\302\233\261\001\221\076\026\156\021\275\137\064\030\157\246\300\245\125\311\002\153\045\152\150\140\364\206\153\326\320\265\277\220\142\160\206\306\024\221\063\370\050\054\346\311\263\142\044\102\104\075\136\312\225\235\154\024\312\203\211\321\054\100\150\265\003\344\343\303\233\143\133\352\044\135\235\005\242\125\217\044\234\226\141\300\102\175\056\110\234\245\265\335\342\040\251\003\063\364\206\052\354\171\062\043\307\201\231\175\251\202\146\301\054\120\352\050\262\304\070\347\243\171\353\020\156\312\014\177\326\000\156\233\366\022\363\352\012\105\113\243\275\267\156\200\047\231\056\140\336\001\351\011\117\335\353\063\111\210\071\024\373\027\251\142\032\271\051\331\160\321\001\344\137\202\170\301\113\003\053\312\260\053\321\126\222\322\033\154\134\040\112\273\360\167\324\145\125\073\326\355\246\105\346\303\006\135\063\261\015\121\212\141\341\136\320\360\222\303\042\046\050\032\051\310\240\365\014\336\012\214\146\043\156\051\302\363\020\243\165\316\275\241\334\153\271\241\240\035\256\154\172\272\216\276\334\143\161\247\325\052\254\271\125\370\073\326\344\370\115\051\111\334\301\230\373\167\307\345\315\366\004\013\017\204\372\370\050\010\277\230\125\167\360\242\254\362\354\176\327\300\260\256\212\047\016\225\027\103\377\043\340\262\335\022\351\303\310\050\373\125\230\242\044\141\257\224\325\150\362\222\100\272\050\040\304\131\037\161\300\210\371\156\011\135\331\213\352\344\126\127\236\273\272\066\366\331\312\046\023\321\302\156\356\115\214\163\041\172\305\226\053\137\061\107\264\222\350\203\025\227\375\211\266\112\247\375\350\056\031\164\322\366\167\225\004\334\041\103\136\263\020\223\120\165\153\237\332\276\034\157\066\200\201\275\100\262\176\274\271\201\232\165\327\337\213\260\173\260\135\261\272\267\005\244\267\343\161\045\030\143\071\106\112\330\372\252\117\005\054\301\047\051\031\375\343\340\045\273\144\252\216\016\261\374\277\314\045\254\265\367\030\316\117\174\041\202\373\071\072\030\024\260\351\102\111\016\122\323\274\250\027\262\262\156\220\324\311\260\314\070\140\212\154\357\136\261\123\257\010\130\254\310\147\311\222\052\355\103\273\147\327\263\072\314\121\223\023\322\215\101\245\306\376\154\363\131\135\325\356\143\360\244\304\006\132\010\065\220\262\165\170\213\356\172\330\165\247\370\215\327\067\040\160\214\154\154\016\317\037\103\273\252\332\346\362\010\125\177\334\007\275\116\331\037\210\316\114\015\350\102\166\034\160\301\206\277\332\372\374\104\110\064\275\064\030\276\102\123\247\036\257\101\327\030\165\072\320\167\124\312\076\377\325\226\013\003\066\230\027\225\162\024\046\200\065\231\355\133\053\165\026\222\016\374\276\062\255\244\274\366\307\073\322\236\077\241\122\331\255\354\243\140\040\375\356\356\033\163\225\041\323\352\214\015\244\227\000\075\361\121\070\227\260\365\107\224\250\163\147\013\215\223\274\312\052\344\176\144\102\113\164\043\341\360\170\331\125\113\265\043\054\306\336\212\256\233\203\372\133\225\020\276\263\234\317\113\116\035\234\017\031\325\341\177\130\345\270\160\135\232\150\067\247\331\277\231\315\023\070\172\362\126\250\111\026\161\361\362\362\052\362\123\274\377\124\266\163\031\233\333\175\005\330\020\144\357\005\370\017\001\123\320\276\171\031\150\113\043\332\215\102\377\076\377\333\174\240\230\120\063\363\211\030\037\107\145\221\070\000\075\161\053\136\300\246\024\323\034\307\110\177\122\336\206\144\221\152\367\234\230\105\153\054\224\250\003\200\203\333\125\071\036\064\165\206\042\120\047\112\035\342\130\117\354\227\137\260\225\066\171\054\373\374\366\031\050\126\314\166\353\133\023\334\107\011\342\367\060\035\337\362\156\301\262\075\342\321\210\311\231\026\154\164\341\341\113\274\025\364\127\317\116\107\032\341\075\313\335\234\120\364\326\106\374\142\170\350\376\176\266\313\134\224\020\017\250\160\030\163\200\267\167\355\031\327\206\217\330\312\174\353\177\247\325\314\206\034\133\332\311\216\164\225\353\012\054\356\301\222\112\351\171\364\114\123\220\353\355\335\306\135\156\301\022\207\331\170\270\337\006\102\031\274\126\171\367\327\262\144\247\157\362\162\262\254\237\057\174\374\237\334\373\152\121\102\202\100\002\172\375\235\122\247\233\144\174\220\302\160\236\006\016\327\017\207\051\235\327\230\326\217\117\255\323\332\154\121\330\071\370\121\371\217\147\204\013\226\116\276\163\370\316\304\025\162\123\216\306\274\023\020\064\312\050\224\353\163\153\073\332\223\331\365\366\372\157\154\017\003\316\103\066\053\204\024\224\003\125\373\124\323\337\335\003\143\072\341\010\363\336\076\274\205\243\377\121\357\356\243\274\054\362\176\026\130\361\170\236\346\022\310\075\017\137\325\157\174\320\161\223\016\051\106\276\356\312\240\115\314\352\237\227\170\140\001\107\136\002\224\274\050\122\366\056\265\323\233\271\373\356\367\131\026\357\344\112\146\056\312\343\176\336\047\351\326\352\337\336\270\370\262\262\333\314\277\226\372\155\272\367\062\037\260\347\001\364\324\051\302\364\334\321\123\242\164\045\164\022\156\136\254\314\167\150\152\317\156\076\344\217\102\067\146\340\374\106\150\020\251\005\377\124\123\354\231\211\173\126\274\125\335\111\271\221\024\057\145\004\077\055\164\116\353\223\133\247\364\357\043\317\200\314\132\212\063\135\066\031\327\201\347\105\110\046\337\162\016\354\202\340\140\064\304\106\231\265\360\304\112\207\207\165\056\005\177\243\101\233\133\260\342\135\060\230\036\101\313\023\141\062\055\272\217\151\223\034\364\057\255\077\073\316\155\355\133\213\374\075\040\242\024\210\141\262\257\301\105\142\335\322\177\022\211\172\277\006\205\050\215\314\134\111\202\370\046\002\150\106\242\113\367\176\070\074\172\254\253\032\266\222\262\236\330\300\030\246\137\075\302\270\177\366\031\246\063\304\033\117\255\261\307\207\045\301\370\371\042\366\000\227\207\261\226\102\107\337\001\066\261\274\141\112\265\165\305\232\026\320\211\221\173\324\250\266\360\115\225\305\201\047\232\023\233\340\237\317\156\230\244\160\240\274\354\241\221\374\344\166\371\067\000\041\313\300\125\030\247\357\323\135\211\330\127\174\231\012\136\031\226\033\241\142\003\311\131\311\030\051\272\164\227\317\374\273\113\051\105\106\105\117\245\070\212\043\242\056\200\132\134\243\137\225\145\230\204\213\332\147\206\025\376\302\212\375\135\246\032\000\000\000\006\263\046\111\063\023\005\074\355\070\166\333\235\043\161\110\030\033\161\163\274\175\004\054\357\264\333\351\115\056\130\315\041\247\151\333\106\127\241\003\047\233\250\357\072\142\234\250\116\350\066\027\052\234\120\345\037\105\130\027\101\317\200\203\025\013\111\034\264\354\273\253\354\022\216\174\201\244\156\142\246\173\127\144\012\012\170\276\034\277\175\331\324\031\241\014\330\150\155\026\142\032\200\201\153\375\265\275\305\142\021\327\054\247\013\201\361\021\175\022\225\051\247\127\014\367\234\365\052\160\050\244\205\070\354\335\073\070\323\325\326\055\046\044\145\225\304\373\163\245\045\245\355\054\060\122\116\273\035\214\310\056\014\031\274\111\167\306\211\217\371\137\323\323\020\260\272\347\026\226\316\371\074\152\125\044\126\277\226\351\320\165\343\203\273\165\103\306\165\204\053\257\277\307\315\270\204\203\263\047\154\051\324\360\243\101\302\324\006\344\015\106\123\267\344\320\105\205\032\317\152\012\016\251\307\020\270\005\314\355\106\065\356\214\020\163\142\360\374\215\200\301\115\012\304\234\121\147\003\322\155\024\165\057\064\301\300\322\304\044\165\201\301\214\054\364\336\110\351\316\224\233\347\310\210\351\312\353\344\244\025\342\221\375\020\175\041\334\037\010\113\021\130\040\202\111\362\217\117\174\176\223\033\247\263\275\015\202\112\105\160\000\000\000\005\000\000\000\004\041\137\203\267\314\271\254\274\320\215\271\173\015\004\334\053\241\315\003\130\063\340\351\000\131\140\077\046\340\172\322\252\321\122\063\216\172\136\131\204\274\325\367\273\116\272\100\267\000\000\000\004\000\000\000\004\016\261\355\124\242\106\015\121\043\210\312\325\063\023\215\044\005\064\351\173\036\202\323\073\331\047\322\001\337\302\116\273\021\263\144\220\043\151\157\205\025\013\030\236\120\300\016\230\205\012\303\103\247\173\066\070\061\234\064\175\163\020\046\235\073\167\024\372\100\153\214\065\260\041\325\115\117\332\332\173\234\345\324\272\133\006\161\236\162\252\365\214\132\256\172\312\005\172\240\342\347\116\175\317\321\172\010\043\102\235\266\051\145\267\325\143\305\173\114\354\224\054\310\145\342\234\035\255\203\312\310\264\326\032\254\304\127\363\066\346\241\013\146\062\077\130\207\277\065\043\337\312\336\341\130\120\073\372\250\235\306\277\131\332\250\052\375\053\136\273\052\234\246\127\052\140\147\316\347\303\047\351\003\233\073\156\246\241\355\307\375\303\337\222\172\255\341\014\034\237\055\137\364\106\105\015\052\071\230\320\371\366\040\053\136\007\303\371\175\044\130\306\235\074\201\220\144\071\170\327\247\364\326\116\227\343\361\304\240\212\174\133\300\077\325\126\202\300\027\342\220\176\253\007\345\273\057\031\001\103\107\132\140\103\325\346\325\046\064\161\364\356\317\156\045\165\373\306\377\067\355\372\044\235\154\332\032\011\367\227\375\132\074\325\072\006\147\000\364\130\143\360\113\154\212\130\317\323\101\044\036\000\055\015\054\002\027\107\053\361\213\143\152\345\107\301\167\023\150\331\363\027\203\134\233\016\364\060\263\337\100\064\366\257\000\320\332\104\364\257\170\000\274\172\134\370\245\253\333\022\334\161\213\125\233\164\312\271\011\016\063\314\130\251\125\060\011\201\304\040\304\332\217\375\147\337\124\010\220\240\142\376\100\333\250\262\301\305\110\316\322\044\163\041\234\123\111\021\324\214\312\253\373\161\274\161\206\057\112\044\353\323\166\322\210\375\116\157\260\156\330\160\127\207\305\376\334\201\074\322\151\176\133\032\254\034\355\105\166\173\024\316\210\100\236\256\273\140\032\223\125\232\256\211\076\024\075\034\071\133\303\046\332\202\035\171\251\355\101\334\373\345\111\024\177\161\300\222\364\363\254\122\053\134\305\162\220\160\146\120\110\173\256\233\265\147\036\314\234\314\054\345\036\255\207\254\001\230\122\150\122\022\042\373\220\127\337\176\324\030\020\265\357\015\117\174\306\163\150\311\017\127\073\032\302\316\225\154\066\136\323\216\211\074\347\262\372\341\135\066\205\243\337\057\243\324\314\011\217\245\175\326\015\054\227\124\250\255\351\200\255\017\223\366\170\160\165\303\366\200\242\272\031\066\250\306\035\032\365\052\267\342\037\101\153\340\235\052\215\144\303\323\330\130\051\150\302\203\231\002\042\237\205\256\342\227\347\027\300\224\310\337\112\043\273\135\266\130\335\067\173\360\364\377\077\375\217\272\136\070\072\110\127\110\002\355\124\133\276\172\153\107\123\123\063\123\327\067\006\006\166\100\023\132\174\345\027\047\234\326\203\003\227\107\322\030\144\174\206\340\227\260\332\242\207\055\124\270\363\345\010\131\207\142\225\107\270\060\330\021\201\141\266\120\171\376\173\305\232\231\351\303\307\070\016\076\160\267\023\217\345\331\276\045\121\120\053\151\215\011\256\031\071\162\362\175\100\363\215\352\046\112\001\046\346\067\327\112\344\311\052\142\111\372\020\064\066\323\353\015\100\051\254\161\053\374\172\136\254\275\327\121\215\155\117\351\003\245\256\145\122\174\326\133\260\324\351\222\134\242\117\327\041\115\306\027\301\120\124\116\102\077\105\014\231\316\121\254\200\005\323\072\315\164\361\276\323\261\173\162\146\244\243\273\206\332\176\272\200\261\001\341\134\267\235\351\242\007\205\054\371\022\111\357\110\006\031\377\052\370\312\274\250\061\045\321\372\251\114\273\012\003\251\006\366\203\263\364\172\227\310\161\375\121\076\121\012\172\045\362\203\261\226\007\127\170\111\141\122\251\034\053\371\332\166\353\340\211\364\145\110\167\362\325\206\256\161\111\304\006\346\143\352\336\262\265\307\350\044\051\271\350\313\110\064\310\064\144\360\171\231\123\062\344\263\310\365\247\053\264\270\306\367\113\015\105\334\154\037\171\225\054\013\164\040\337\122\136\067\301\123\167\265\360\230\103\031\303\231\071\041\345\314\331\176\011\165\222\006\105\060\323\075\343\257\255\127\063\313\347\160\074\122\226\046\077\167\064\056\373\365\240\107\125\260\263\311\227\304\062\204\143\350\114\252\055\343\377\334\322\227\272\252\254\327\256\144\156\104\265\300\361\140\104\337\070\372\275\051\152\107\263\250\070\251\023\230\057\262\343\160\300\170\355\260\102\310\115\263\114\343\153\106\314\267\144\140\246\220\314\206\303\002\105\175\321\315\341\227\354\200\165\350\053\071\075\124\040\165\023\116\052\027\356\160\245\341\207\007\135\003\256\074\205\074\377\140\162\233\244\000\000\000\005\115\341\366\226\133\332\274\147\154\132\115\307\303\137\227\370\054\260\343\034\150\320\117\035\255\226\061\117\360\236\153\075\351\152\356\343\000\321\366\213\361\274\251\374\130\344\003\043\066\315\201\232\257\127\207\104\345\015\023\127\240\344\050\147\004\323\101\252\012\063\173\031\376\113\304\074\056\171\226\115\117\065\020\211\362\340\344\034\174\103\256\015\111\347\364\004\260\367\133\350\016\243\257\011\214\227\122\102\012\212\300\352\053\273\037\116\353\240\122\070\256\360\330\316\143\360\306\345\344\004\035\225\071\212\157\177\076\016\351\174\301\131\030\111\324\355\043\143\070\261\107\253\336\237\121\357\237\324\341\301", 3860);
  try {
    vk.verify(message, signature);
    Serial.println("Vaild (-:");
  }
  catch (INVALID &e) {
    Serial.println("Invaild )-:");
    Serial.println(e.what());
  }
}

void loop() {
  // put your main code here, to run repeatedly:
}
