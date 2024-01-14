from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

def test_poly_interpolate_at(galois_field, polynomial):
    # Take x^2 + 10 as the polynomial
    poly = polynomials_over(ZR)
    # values = [(i+1, pow(i+1, 2) + 10) for i in range(3)]
    values = [(1, 0x0933983192abe79dbad09eade60761956c3007be593e1f4d0be2cc5bc602a679), (2, 0x126730632557cf3b75a13d5bcc0ec32ad8600f7cb27c3e9a17c598b78c054cf2), 
              (3, 0x1b9ac894b803b6d93071dc09b21624c04490173b0bba5de723a865135207f36b), (4, 0x24ce60c64aaf9e76eb427ab7981d8655b0c01ef964f87d342f8b316f180a99e4)]
    print(values)
    # k = galois_field.random()
    k = 0
    res = poly.interpolate_at(values, k)
    print("k=0", res)
    # assert polynomial.interpolate_at(values, k) == pow(k, 2) + 10

    # 0 res: 0x0933983192abe79dbad09eade60761956c3007be593e1f4d0be2cc5bc602a679
    # 1 res: 0x126730632557cf3b75a13d5bcc0ec32ad8600f7cb27c3e9a17c598b78c054cf2
    # 2 res: 0x1b9ac894b803b6d93071dc09b21624c04490173b0bba5de723a865135207f36b
    # 3 res: 0x24ce60c64aaf9e76eb427ab7981d8655b0c01ef964f87d342f8b316f180a99e4

    
  