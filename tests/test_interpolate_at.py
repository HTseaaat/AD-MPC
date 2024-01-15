from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

def test_poly_interpolate_at(galois_field, polynomial):
    # Take x^2 + 10 as the polynomial
    poly = polynomials_over(ZR)
    # values = [(i+1, pow(i+1, 2) + 10) for i in range(3)]
    values = [(1, 0x21aae7715a385f4a2bdd9a44500c6c88e2ce976d01e549641979c52c83b61192), (2, 0x4355cee2b470be9457bb3488a018d911c59d2eda03ca92c832f38a59076c2321), 
              (3, 0x6500b6540ea91dde8398ceccf025459aa86bc64705afdc2c4c6d4f858b2234b0)]
    print(values)
    # k = galois_field.random()
    k = 0
    res = poly.interpolate_at(values, k)
    print("k=0", res)
    # assert polynomial.interpolate_at(values, k) == pow(k, 2) + 10

    # 0 res: 0x21aae7715a385f4a2bdd9a44500c6c88e2ce976d01e549641979c52c83b61192
    # 1 res: 0x4355cee2b470be9457bb3488a018d911c59d2eda03ca92c832f38a59076c2321
    # 2 res: 0x6500b6540ea91dde8398ceccf025459aa86bc64705afdc2c4c6d4f858b2234b0
    # 3 res: 0x12bdf6723f43ffe07c3c9109368fda1e377cb9b10796c99165e714b30ed8463e

    
  