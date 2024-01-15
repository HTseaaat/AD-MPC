from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

def test_poly_interpolate_at(galois_field, polynomial):
    # Take x^2 + 10 as the polynomial
    poly = polynomials_over(ZR)
    # values = [(i+1, pow(i+1, 2) + 10) for i in range(3)]
    values = [(1, 0x2), (2, 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFFF), 
              (3, 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFFB)]
    print(values)
    # k = galois_field.random()
    k = 0
    res = poly.interpolate_at(values, k)
    print("k=0", res)
    # assert polynomial.interpolate_at(values, k) == pow(k, 2) + 10

    # 0 res: 0x2
    # 1 res: 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFFF
    # 2 res: 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFFB
    # 3 res: 0x12bdf6723f43ffe07c3c9109368fda1e377cb9b10796c99165e714b30ed8463e

    
  