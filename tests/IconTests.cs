// Copyright (c) EurekaGao. Verify real Windows icon decoding and transparency.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

internal static class IconTests
{
    [DllImport("user32.dll")]
    private static extern IntPtr CreateIconFromResourceEx(byte[] data, uint length, bool icon, uint version, int width, int height, uint flags);
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);
    private static int checks;
    private static void Check(bool result, string name)
    {
        if (!result) throw new Exception(name);
        checks++; Console.WriteLine("PASS " + name);
    }
    private static void CheckPixels(Bitmap image, string name)
    {
        Check(image.GetPixel(0, 0).A == 0 && image.GetPixel(image.Width - 1, 0).A == 0 &&
            image.GetPixel(0, image.Height - 1).A == 0 && image.GetPixel(image.Width - 1, image.Height - 1).A == 0,
            name + " transparent corners");
        Check(image.GetPixel(image.Width / 2, image.Height / 2).A >= 240, name + " visible artwork");
        HashSet<int> colors = new HashSet<int>();
        for (int y = 0; y < image.Height; y++)
            for (int x = 0; x < image.Width; x++)
            {
                Color color = image.GetPixel(x, y);
                if (color.A >= 16 && (x < image.Width / 8 || x >= image.Width * 7 / 8 ||
                    y < image.Height / 8 || y >= image.Height * 7 / 8)) CheckNoWhiteMatte(color, name);
                if (color.A >= 240) colors.Add(color.ToArgb());
            }
        Check(colors.Count > (image.Width >= 32 ? 128 : 16), name + " full-color gradient");
    }
    private static void CheckNoWhiteMatte(Color color, string name)
    {
        // The outer tile is dark green; inner artwork may contain bright highlights.
        if (color.R > 225 && color.G > 225 && color.B > 225)
            throw new Exception(name + " contains white matte pixels");
    }
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 3) throw new ArgumentException("Expected ICO, EXE and preview directory.");
            byte[] bytes = File.ReadAllBytes(args[0]);
            int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
            Check(BitConverter.ToUInt16(bytes, 2) == 1 && BitConverter.ToUInt16(bytes, 4) == sizes.Length, "ICO frame directory");
            Directory.CreateDirectory(args[2]);
            using (Bitmap sheet = new Bitmap(650, 780))
            using (Graphics canvas = Graphics.FromImage(sheet))
            {
                Color[] backgrounds = { Color.FromArgb(30, 30, 30), Color.White, Color.FromArgb(109, 77, 93) };
                for (int row = 0; row < backgrounds.Length; row++)
                    using (Brush brush = new SolidBrush(backgrounds[row])) canvas.FillRectangle(brush, 0, row * 260, sheet.Width, 260);
                int left = 8;
                for (int i = 0; i < sizes.Length; i++)
                {
                    int entry = 6 + i * 16, size = sizes[i];
                    int length = checked((int)BitConverter.ToUInt32(bytes, entry + 8));
                    int offset = checked((int)BitConverter.ToUInt32(bytes, entry + 12));
                    int stride = ((size + 31) / 32) * 4;
                    Check((bytes[entry] == 0 ? 256 : bytes[entry]) == size &&
                        BitConverter.ToUInt16(bytes, entry + 6) == 32 && BitConverter.ToUInt16(bytes, offset + 14) == 32 &&
                        BitConverter.ToInt32(bytes, offset + 4) == size && BitConverter.ToInt32(bytes, offset + 8) == size * 2 &&
                        length == 40 + size * size * 4 + stride * size && offset + length <= bytes.Length,
                        size + " px DIB dimensions and bit depth");
                    bool validMask = true;
                    for (int y = 0; y < size; y++)
                        for (int x = 0; x < size; x++)
                        {
                            bool transparent = bytes[offset + 40 + (y * size + x) * 4 + 3] == 0;
                            bool masked = (bytes[offset + 40 + size * size * 4 + y * stride + x / 8] & (0x80 >> (x % 8))) != 0;
                            if (transparent != masked) validMask = false;
                        }
                    Check(validMask, size + " px alpha and AND mask agree");
                    byte[] frame = new byte[length]; Array.Copy(bytes, offset, frame, 0, length);
                    IntPtr handle = CreateIconFromResourceEx(frame, (uint)length, true, 0x30000, size, size, 0);
                    Check(handle != IntPtr.Zero, size + " px Windows native decode");
                    try
                    {
                        using (Icon icon = Icon.FromHandle(handle))
                        using (Bitmap image = icon.ToBitmap())
                        {
                            Check(image.Width == size && image.Height == size, size + " px native render dimensions");
                            CheckPixels(image, size + " px");
                            for (int row = 0; row < backgrounds.Length; row++) canvas.DrawImageUnscaled(image, left, row * 260 + 2);
                        }
                    }
                    finally { DestroyIcon(handle); }
                    left += size + 8;
                }
                sheet.Save(Path.Combine(args[2], "backgrounds.png"), ImageFormat.Png);
            }
            using (Icon icon = Icon.ExtractAssociatedIcon(args[1]))
            using (Bitmap image = icon.ToBitmap()) CheckPixels(image, "compiled EXE");
            Console.WriteLine("SUCCESS " + checks + " icon checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
