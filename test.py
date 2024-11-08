from function import SingFunctionNamePrediction
import logging
# 设置日志配置
logging.basicConfig(
    level=logging.DEBUG,  # 设置最低级别为DEBUG
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

if __name__ == "__main__":

    sfnp = SingFunctionNamePrediction(name_only=True)

    func_pseudocode = \
"""
int __fastcall sub_80633D9(int a1, const char *a2)
{
  int v3; // esi
  int v4; // ebx
  int v5; // esi
  unsigned __int8 *i; // eax
  unsigned __int8 v7; // cl

  sub_8063356();
  v3 = dword_80DBB80;
  v4 = dword_80DBB80 + 104;
  if ( !fgets_unlocked() )
    sub_804D3C9((int)"error getting response");
  *(_BYTE *)(v3 + 80) = 0;
  v5 = *(unsigned __int8 *)strchrnul();
  for ( i = (unsigned __int8 *)v4; ; ++i )
  {
    v7 = *i;
    if ( !*i )
      break;
    if ( v7 <= 0x1Fu )
    {
      if ( v7 != 9 )
        break;
      *i = 32;
    }
  }
  *i = 0;
  if ( a2 && (dword_80DBB9C & 4) != 0 )
    fprintf(stderr, a2, v4);
  return v5;
}
"""

    print(sfnp.prediction(function_content=func_pseudocode)) 


'''
Let's break down the pseudocode step by step to suggest a more meaningful function name.

1. **Infer Variable Names:**
   - `v2` is an array of three integers, and it seems to be used to hold a signal set. Therefore, a more appropriate name could be `signal_set`.

2. **Analyze Code Behavior:**
   - The function receives an integer `a1` as an argument, which likely represents a signal number given its use in `sigaddset`.
   - `v2[0]` and `v2[1]` are initialized to 0, preparing an empty signal set.
   - The call to `sigaddset((sigset_t *)v2, a1);` adds the signal number `a1` to the signal set `v2`.
   - Finally, `sigprocmask(1, (const sigset_t *)v2, 0);` is called. This function modifies the signal mask, and with the first argument as `1` (usually `SIG_BLOCK`), it indicates blocking the given signal.
   - The function returns the result of `sigprocmask`, which typically indicates success or failure.

3. **Rename the Function:**
   - The purpose of this function is to block a specific signal identified by `a1`. Therefore, an appropriate name for the function could be `block_signal`.

Conclusion:
The function's behavior adds a signal specified by `a1` to the mask and blocks it, given how it interacts with the system's signal handling. Hence, `block_signal` is a fitting and descriptive name for this function.
'''