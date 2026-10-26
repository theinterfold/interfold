#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
"""Estimate how much of the demand curve the two-round probe search reveals.

Model (an assumption, not a measurement): bids are iid. The step b is a rounded normal
(median 8, sigma 3, clipped to 0..15). The budget B in units is lognormal (median 100, sigma 1).
The curve level sum is F_m = sum_i B_i * [b_i >= m]. For n independent bidders the vector
(F_m) is approximately Gaussian with covariance
  Cov(F_a, F_b) = n * (E[B^2] * q(max(a, b)) - E[B]^2 * q(a) * q(b)),  q(m) = P(b >= m).
The script prints the differential entropy of the revealed sums and of all 15 sums (F_1..F_15),
at a resolution of 1 budget unit. Only the ratio and the difference are meaningful.
Run: python3 scripts/leak_entropy.py
"""
import math
L=16
def ncdf(x): return 0.5*(1+math.erf(x/math.sqrt(2)))
def q_table(med=8.0,sig=3.0):
    # b = clip(round(N(med,sig)),0,15); q[m] = P(b >= m)
    q=[1.0]*(L+1)
    for m in range(1,L):
        q[m]=1-ncdf((m-0.5-med)/sig)
    q[L]=0.0
    return q
def logdet(C):
    k=len(C); A=[r[:] for r in C]; ld=0.0
    for i in range(k):
        p=max(range(i,k),key=lambda r:abs(A[r][i]))
        A[i],A[p]=A[p],A[i]
        ld+=math.log(abs(A[i][i]))
        for r in range(i+1,k):
            f=A[r][i]/A[i][i]
            for c in range(i,k): A[r][c]-=f*A[i][c]
    return ld
def H(levels,n,q,EB,EB2):
    k=len(levels)
    C=[[n*(EB2*q[max(a,b)]-EB*EB*q[a]*q[b]) for b in levels] for a in levels]
    return 0.5*(k*math.log2(2*math.pi*math.e)+logdet(C)/math.log(2))
mu,s=math.log(100),1.0
EB=math.exp(mu+s*s/2); EB2=math.exp(2*mu+2*s*s)
for med,sig,name in ((8.0,3.0,"mid-curve bids"),):
  q=q_table(med,sig)
  for n in (85,30):
    full=list(range(1,16))
    Hf=H(full,n,q,EB,EB2)
    print(f"n={n} ({name}): full curve F1..F15 = {Hf:.1f} bits")
    print(f"   round 1 alone {{4,8,12}} = {H([4,8,12],n,q,EB,EB2):.1f} bits")
    for lo in (0,4,8,12):
        hi=lo+4 if lo<12 else 16
        P2=list(range(lo+1,hi))
        S=sorted(set([4,8,12]+P2))
        h=H(S,n,q,EB,EB2)
        cnt=len(S)+(1 if lo==0 else 0)
        print(f"   lo={lo:2d}: sums at {S}{' +F0' if lo==0 else ''} ({cnt} sums): {h:.1f} bits = {100*h/Hf:.0f}% of full, hidden {Hf-h:.1f} bits")
