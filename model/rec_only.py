from wp_model import *
for cfg in [(3,1,3,1,0),(3,1,3,1,1),(3,0,2,1,1),(3,0,2,1,2),(4,0,3,1,1)]:
    nh,nb,T,R,off=cfg; tot,ok=recovery_from_all_stuck(nh,nb,T,R,off)
    print(f'n={nh+nb} b={nb} c={off} T={T}: {ok}/{tot} stuck splits recover (n-b-c={nh-off} {">=" if nh-off>=T else "<"} T)', flush=True)
