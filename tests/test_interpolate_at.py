from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

def test_poly_interpolate_at(galois_field, polynomial):
    # Take x^2 + 10 as the polynomial
    poly = polynomials_over(ZR)
    # values = [(i+1, pow(i+1, 2) + 10) for i in range(3)]
    values = [(1, 0x30f2967da20b737dda28bc706f1466db7378653156b33b64f1d70d18ca440c0b), (2, 0x61e52cfb4416e6fbb45178e0de28cdb6e6f0ca62ad6676c9e3ae1a3194881813), 
              (3, 0x1eea1c25bc84dd315b405d49439b5c8d06ab8b91041b562fd585274b5ecc241a)]
    print(values)
    # k = galois_field.random()
    k = 0
    res = poly.interpolate_at(values, k)
    print("k=0", res)
    # assert polynomial.interpolate_at(values, k) == pow(k, 2) + 10

    # 0 res: 0x30f2967da20b737dda28bc706f1466db7378653156b33b64f1d70d18ca440c0b
    # 1 res: 0x61e52cfb4416e6fbb45178e0de28cdb6e6f0ca62ad6676c9e3ae1a3194881813
    # 2 res: 0x1eea1c25bc84dd315b405d49439b5c8d06ab8b91041b562fd585274b5ecc241a
    # 3 res: 0x4fdcb2a35e9050af356919b9b2afc3687a23f0c25ace9194c75c346429103022

    # 0 test_add: 0602eec300e91641695da3986043571ddf576017c3fe5b1e651af988eb8f2b0a
    # 1 test_add: 0c05dd8601d22c82d2bb4730c086ae3bbeaec02f87fcb63cca35f311d71e5608
    # 2 test_add: 0208cc4902bb42c43c18eac920ca055989272668a9037484d73e898065b7ad19
    # 3 test_add: 080bbb0c03a45905a5768e61810d5c77687e86806d01cfa33c5983095146d817

    # 0 test_add: Fr(0x707823807fc4238645a676a24ac3aa9df86d7448dbf332a54d589657f66409db)
    # 1 test_add: Fr(0x6d029fadd5eac9c45813153c8be57d369d1d448eb7e8094b9ab12cb0ecc813a9)
    # 2 test_add: Fr(0x698d1bdb2c1170026a7fb3d6cd074fcf41cd14d493dcdff1e809c309e32c1d77)
    # 3 test_add: Fr(0x66179808823816407cec52710e292267e67ce51a6fd1b69835625962d9902745)

    # 0 0x18F640652F57E397540EBB553EB5C2BA0BC1044625158461BF0CD3033D3F776F
    # 1 0x31EC80CA5EAFC72EA81D76AA7D6B85741782088C4A2B08C37E19A6067A7EEEDB
    # 2 0x4AE2C12F8E07AAC5FC2C31FFBC21482E23430CD26F408D253D267909B7BE6647
    # 3 0x63D90194BD5F8E5D503AED54FAD70AE82F04111894561186FC334C0CF4FDDDB3
    